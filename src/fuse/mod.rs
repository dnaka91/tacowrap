#![allow(clippy::cast_possible_truncation)]

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::{File, Metadata},
    io::Read,
    os::unix::prelude::*,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use bitflags::bitflags;
use fuser::FileAttr;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::gocryptfs::{
    self,
    content::{FileHeader, BLOCK_SIZE},
    DynCipher, MasterKey,
};

mod interface;
mod wrapper;

#[allow(dead_code)]
pub struct Fuse {
    base_dir: PathBuf,
    master_key: MasterKey,
    cipher: DynCipher,
    dirs: FxHashMap<u64, FuseDir>,
    files: FxHashMap<u64, FuseFile>,
    handles: FxHashMap<u64, File>,
    shutdown: Option<flume::Sender<()>>,
}

struct FuseDir {
    path: PathBuf,
    name: OsString,
    attr: FileAttr,
    children: FxHashSet<u64>,
    iv: gocryptfs::names::Iv,
}

#[allow(dead_code)]
struct FuseFile {
    parent: u64,
    path: PathBuf,
    name: OsString,
    attr: FileAttr,
    head: FileHeader,
}

fn file_size(cipher: &DynCipher, meta: &std::fs::Metadata) -> (u64, u64) {
    let size = meta.size() as usize;
    if size == 0 {
        return (0, 0);
    }

    let (size, blocks) = cipher.to_plain::<BLOCK_SIZE>(size - FileHeader::LEN);
    (size as u64, blocks as u64)
}

fn file_head(path: &Path) -> Result<FileHeader> {
    let mut file = std::fs::File::open(path)?;
    let mut head = [0; FileHeader::LEN];

    file.read_exact(&mut head)?;

    FileHeader::read(&head).map(|v| v.0)
}

impl Fuse {
    #[allow(clippy::too_many_lines)]
    pub fn new(
        base_dir: PathBuf,
        master_key: MasterKey,
        root_iv: gocryptfs::names::Iv,
        flags: &BTreeSet<gocryptfs::config::Flag>,
    ) -> Result<Self> {
        let cipher = DynCipher::new(flags);
        let meta = base_dir.metadata()?;
        let mut dirs = FxHashMap::default();
        let mut files = FxHashMap::default();
        let mut children = FxHashSet::default();

        for entry in std::fs::read_dir(&base_dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let file_name = entry.file_name();
            let path = entry.path();

            if gocryptfs::is_crypto_dir(file_type, &path) {
                let name = gocryptfs::names::decrypt(&master_key, &root_iv, &file_name)
                    .with_context(|| {
                        format!(
                            "failed decrypting directory name `{}`",
                            file_name.to_string_lossy()
                        )
                    })?;
                let meta = entry.metadata()?;
                let iv = gocryptfs::names::load_iv(&path)?;

                dirs.insert(
                    meta.ino(),
                    FuseDir {
                        path,
                        name,
                        attr: dir_attr(&meta)?,
                        children: FxHashSet::default(),
                        iv,
                    },
                );
                children.insert(meta.ino());
            } else if gocryptfs::is_crypto_file(file_type, &file_name) {
                let name = gocryptfs::names::decrypt(&master_key, &root_iv, &file_name)
                    .with_context(|| {
                        format!(
                            "failed decrypting file name `{}`",
                            file_name.to_string_lossy()
                        )
                    })?;
                let head = file_head(&path)?;
                let meta = entry.metadata()?;
                let (size, blocks) = file_size(&cipher, &meta);

                files.insert(
                    meta.ino(),
                    FuseFile {
                        parent: fuser::FUSE_ROOT_ID,
                        path,
                        name,
                        attr: file_attr(&meta, size, blocks)?,
                        head,
                    },
                );
                children.insert(meta.ino());
            }
        }

        dirs.insert(
            fuser::FUSE_ROOT_ID,
            FuseDir {
                path: base_dir.clone(),
                name: OsString::new(),
                attr: FileAttr {
                    ino: fuser::FUSE_ROOT_ID,
                    size: 0,
                    blocks: 0,
                    atime: meta.accessed()?,
                    mtime: meta.modified()?,
                    ctime: meta.created()?,
                    crtime: meta.created()?,
                    kind: fuser::FileType::Directory,
                    perm: 0o755,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                },
                children,
                iv: root_iv,
            },
        );

        Ok(Self {
            base_dir,
            master_key,
            cipher,
            dirs,
            files,
            handles: FxHashMap::default(),
            shutdown: None,
        })
    }

    pub fn with_shutdown(mut self, sender: flume::Sender<()>) -> Self {
        self.shutdown = Some(sender);
        self
    }

    #[allow(clippy::type_complexity)]
    fn read_dir(
        &self,
        dir: &FuseDir,
    ) -> Result<(
        FxHashMap<u64, FuseDir>,
        FxHashMap<u64, FuseFile>,
        FxHashSet<u64>,
    )> {
        let mut dirs = FxHashMap::default();
        let mut files = FxHashMap::default();
        let mut children = FxHashSet::default();

        for entry in std::fs::read_dir(&dir.path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let file_name = entry.file_name();
            let path = entry.path();

            if gocryptfs::is_crypto_dir(file_type, &path) {
                let name = gocryptfs::names::decrypt(&self.master_key, &dir.iv, &file_name)?;
                let meta = entry.metadata()?;
                let iv = gocryptfs::names::load_iv(&path)?;

                dirs.insert(
                    meta.ino(),
                    FuseDir {
                        path,
                        name,
                        attr: dir_attr(&meta)?,
                        children: FxHashSet::default(),
                        iv,
                    },
                );
                children.insert(meta.ino());
            } else if gocryptfs::is_crypto_file(file_type, &file_name) {
                let name = gocryptfs::names::decrypt(&self.master_key, &dir.iv, &file_name)?;
                let head = file_head(&path)?;
                let meta = entry.metadata()?;
                let (size, blocks) = file_size(&self.cipher, &meta);

                files.insert(
                    meta.ino(),
                    FuseFile {
                        parent: fuser::FUSE_ROOT_ID,
                        path,
                        name,
                        attr: file_attr(&meta, size, blocks)?,
                        head,
                    },
                );
                children.insert(meta.ino());
            }
        }

        Ok((dirs, files, children))
    }

    fn find_dir(&self, parent: u64, name: &OsStr) -> Option<&FuseDir> {
        let parent = self.dirs.get(&parent)?;
        parent.children.iter().find_map(|c| {
            let dir = self.dirs.get(c)?;
            (dir.name == name).then_some(dir)
        })
    }

    fn find_file(&self, parent: u64, name: &OsStr) -> Option<&FuseFile> {
        let parent = self.dirs.get(&parent)?;
        parent.children.iter().find_map(|c| {
            let file = self.files.get(c)?;
            (file.name == name).then_some(file)
        })
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug)]
    struct OpenFlags: i32 {
        /// Open as read-only, mutually exclusive with [`Self::WRONLY`] and [`Self::RDWR`].
        const RDONLY = libc::O_RDONLY;
        /// Open as write-only, mutually exclusive with [`Self::RDONLY`] and [`Self::RDWR`].
        const WRONLY = libc::O_WRONLY;
        /// Open as read/write, mutually exclusive with [`Self::RDONLY`] and [`Self::WRONLY`].
        const RDWR = libc::O_RDWR;

        const APPEND = libc::O_APPEND;
        const ASYNC = libc::O_ASYNC;
        const CLOEXEC = libc::O_CLOEXEC;
        const CREAT = libc::O_CREAT;
        const DIRECT = libc::O_DIRECT;
        const DIRECTORY = libc::O_DIRECTORY;
        const DSYNC = libc::O_DSYNC;
        const EXCL = libc::O_EXCL;
        const LARGEFILE = libc::O_LARGEFILE;
        const NOATIME = libc::O_NOATIME;
        const NOCTTY = libc::O_NOCTTY;
        const NOFOLLOW = libc::O_NOFOLLOW;
        const NONBLOCK = libc::O_NONBLOCK;
        const NDELAY = libc::O_NDELAY;
        const PATH = libc::O_PATH;
        const SYNC = libc::O_SYNC;
        const TMPFILE = libc::O_TMPFILE;
        const TRUNC = libc::O_TRUNC;
    }
}

bitflags! {
    /// File mode flags that define access rights as well as special bits.
    #[derive(Clone, Copy, Debug)]
    #[cfg_attr(test, derive(PartialEq))]
    struct Mode: u32 {
        /// User (file owner) has read, write, and execute permission.
        const USR_RWX = libc::S_IRWXU;
        /// User has read permission.
        const USR_R = libc::S_IRUSR;
        /// User has write permission.
        const USR_W = libc::S_IWUSR;
        /// User has execute permission.
        const USR_X = libc::S_IXUSR;

        /// Group has read, write, and execute permission.
        const GRP_RWX = libc::S_IRWXG;
        /// Group has read permission.
        const GRP_R = libc::S_IRGRP;
        /// Group has write permission.
        const GRP_W = libc::S_IWGRP;
        /// Group has execute permission.
        const GRP_X = libc::S_IXGRP;

        /// Others have read, write, and execute permission.
        const OTH_RWX = libc::S_IRWXO;
        /// Others have read permission.
        const OTH_R = libc::S_IROTH;
        /// Others have write permission.
        const OTH_W = libc::S_IWOTH;
        /// Others have execute permission.
        const OTH_X = libc::S_IXOTH;

        /// Set-user-ID bit.
        const SET_UID = libc::S_ISUID;
        /// Set-group-ID bit.
        const SET_GID = libc::S_ISGID;
        /// Sticky bit.
        const STICKY = libc::S_ISVTX;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug)]
    struct WriteFlags: u32 {
        /// Delayed write from page cache, file handle is guessed.
        const CACHE = fuser::consts::FUSE_WRITE_CACHE;
        /// The `lock_owner`` field is valid.
        const LOCKOWNER = fuser::consts::FUSE_WRITE_LOCKOWNER;
        /// Kill suid and sgid bits.
        const KILL_PRIV = fuser::consts::FUSE_WRITE_KILL_PRIV;
    }
}

fn dir_attr(meta: &Metadata) -> Result<FileAttr> {
    Ok(FileAttr {
        ino: meta.ino(),
        size: 0,
        blocks: 0,
        atime: meta.accessed()?,
        mtime: meta.modified()?,
        ctime: meta.created()?,
        crtime: meta.created()?,
        kind: fuser::FileType::Directory,
        perm: meta.mode().try_into()?,
        nlink: meta.nlink().try_into()?,
        uid: meta.uid(),
        gid: meta.gid(),
        rdev: 0,
        blksize: 512,
        flags: 0,
    })
}

fn file_attr(meta: &Metadata, size: u64, blocks: u64) -> Result<FileAttr> {
    Ok(FileAttr {
        ino: meta.ino(),
        size,
        blocks,
        atime: meta.accessed()?,
        mtime: meta.modified()?,
        ctime: meta.created()?,
        crtime: meta.created()?,
        kind: fuser::FileType::RegularFile,
        perm: meta.mode().try_into()?,
        nlink: meta.nlink().try_into()?,
        uid: meta.uid(),
        gid: meta.gid(),
        rdev: 0,
        blksize: BLOCK_SIZE as u32,
        flags: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_matches() {
        assert_eq!(Mode::USR_RWX, Mode::USR_R | Mode::USR_W | Mode::USR_X);
        assert_eq!(Mode::GRP_RWX, Mode::GRP_R | Mode::GRP_W | Mode::GRP_X);
        assert_eq!(Mode::OTH_RWX, Mode::OTH_R | Mode::OTH_W | Mode::OTH_X);

        assert_eq!(0o7777, Mode::all().bits());
    }
}
