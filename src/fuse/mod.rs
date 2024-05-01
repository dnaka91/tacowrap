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
use log::info;
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
    parent: u64,
    crypt_name: OsString,
    plain_name: OsString,
    attr: FileAttr,
    children: FxHashSet<u64>,
    iv: gocryptfs::names::Iv,
}

#[allow(dead_code)]
struct FuseFile {
    parent: u64,
    crypt_name: OsString,
    plain_name: OsString,
    attr: FileAttr,
    head: Option<FileHeader>,
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

    file.read_exact(&mut head)
        .context("failed reading header content")?;

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

        let mut root = FuseDir {
            parent: 0,
            crypt_name: OsString::new(),
            plain_name: OsString::new(),
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
            children: FxHashSet::default(),
            iv: root_iv,
        };

        read_dir_recursive(
            &master_key,
            &cipher,
            &mut base_dir.clone(),
            &mut root,
            &mut dirs,
            &mut files,
        )?;
        dirs.insert(fuser::FUSE_ROOT_ID, root);

        info!(dirs = dirs.len() - 1, files = files.len(); "taco opened");

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

    fn find_dir(&self, parent: u64, name: &OsStr) -> Option<&FuseDir> {
        let parent = self.dirs.get(&parent)?;
        parent.children.iter().find_map(|c| {
            let dir = self.dirs.get(c)?;
            (dir.plain_name == name).then_some(dir)
        })
    }

    fn find_file(&self, parent: u64, name: &OsStr) -> Option<&FuseFile> {
        let parent = self.dirs.get(&parent)?;
        parent.children.iter().find_map(|c| {
            let file = self.files.get(c)?;
            (file.plain_name == name).then_some(file)
        })
    }

    /// Create the absolute path to a directory.
    fn dir_path(&self, dir: &FuseDir) -> PathBuf {
        self.build_path(&dir.crypt_name, dir.parent)
    }

    /// Create the absolute path to a file.
    fn file_path(&self, file: &FuseFile) -> PathBuf {
        self.build_path(&file.crypt_name, file.parent)
    }

    /// Create the path from the given name, traversing the parent up to the root.
    fn build_path(&self, name: &OsStr, parent: u64) -> PathBuf {
        let mut buf = vec![name];
        let mut ino = parent;

        while let Some(parent) = self.dirs.get(&ino) {
            buf.push(&parent.crypt_name);
            ino = parent.parent;
        }

        self.base_dir.iter().chain(buf.into_iter().rev()).collect()
    }
}

#[allow(clippy::type_complexity)]
fn read_dir(
    master_key: &MasterKey,
    cipher: &DynCipher,
    dir: (u64, &Path, gocryptfs::names::Iv),
) -> Result<(
    FxHashMap<u64, FuseDir>,
    FxHashMap<u64, FuseFile>,
    FxHashSet<u64>,
)> {
    let mut dirs = FxHashMap::default();
    let mut files = FxHashMap::default();
    let mut children = FxHashSet::default();

    for entry in std::fs::read_dir(dir.1)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let file_name = entry.file_name();
        let path = entry.path();

        if gocryptfs::is_crypto_dir(file_type, &path) {
            let name =
                gocryptfs::names::decrypt(master_key, &dir.2, &file_name).with_context(|| {
                    format!(
                        "failed decrypting directory name `{}`",
                        file_name.to_string_lossy()
                    )
                })?;
            let meta = entry.metadata()?;
            let iv = gocryptfs::names::load_iv(&path).context("failed loading directory nonce")?;

            dirs.insert(
                meta.ino(),
                FuseDir {
                    parent: dir.0,
                    crypt_name: file_name,
                    plain_name: name,
                    attr: dir_attr(&meta)?,
                    children: FxHashSet::default(),
                    iv,
                },
            );
            children.insert(meta.ino());
        } else if gocryptfs::is_crypto_file(file_type, &file_name) {
            let name =
                gocryptfs::names::decrypt(master_key, &dir.2, &file_name).with_context(|| {
                    format!(
                        "failed decrypting file name `{}`",
                        file_name.to_string_lossy()
                    )
                })?;
            let meta = entry.metadata()?;
            let head = (meta.size() > 0).then(|| file_head(&path)).transpose()?;
            let (size, blocks) = file_size(cipher, &meta);

            files.insert(
                meta.ino(),
                FuseFile {
                    parent: dir.0,
                    crypt_name: file_name,
                    plain_name: name,
                    attr: file_attr(&meta, size, blocks)?,
                    head,
                },
            );
            children.insert(meta.ino());
        }
    }

    Ok((dirs, files, children))
}

fn read_dir_recursive(
    master_key: &MasterKey,
    cipher: &DynCipher,
    base: &mut PathBuf,
    dir: &mut FuseDir,
    dirs: &mut FxHashMap<u64, FuseDir>,
    files: &mut FxHashMap<u64, FuseFile>,
) -> Result<()> {
    base.push(&dir.crypt_name);

    let (mut found_dirs, found_files, children) =
        read_dir(master_key, cipher, (dir.attr.ino, &base, dir.iv))
            .context("failed reading directory")?;

    for dir in found_dirs.values_mut() {
        read_dir_recursive(master_key, cipher, base, dir, dirs, files)?;
    }

    dirs.extend(found_dirs);
    files.extend(found_files);
    dir.children = children;

    base.pop();

    Ok(())
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
