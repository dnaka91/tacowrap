#![allow(clippy::cast_possible_truncation)]

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::{self, File, Metadata},
    io::{Read, Write},
    os::unix::prelude::*,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{ensure, Context, Result};
use bitflags::bitflags;
use fuser::FileAttr;
use libc::c_int;
use log::{debug, error, trace, warn};
use nix::{
    errno::Errno,
    sys::{
        stat::{FchmodatFlags, UtimensatFlags},
        time::TimeSpec,
    },
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::gocryptfs::{
    self,
    content::{FileHeader, BLOCK_SIZE},
    DynCipher, MasterKey,
};

const TTL: Duration = Duration::from_secs(1);

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
                let name = gocryptfs::names::decrypt(&master_key, &root_iv, &file_name)?;
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
                let name = gocryptfs::names::decrypt(&master_key, &root_iv, &file_name)?;
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

    fn lookup_wrapper(&mut self, parent: u64, name: &OsStr) -> Result<Option<&FileAttr>> {
        let Some(dir) = self.dirs.get(&parent) else {
            return Ok(None);
        };

        let dir = if dir.children.is_empty() {
            let (dirs, files, children) = self.read_dir(dir).context("failed reading directory")?;
            self.dirs.extend(dirs);
            self.files.extend(files);
            let dir = self.dirs.get_mut(&parent).unwrap();
            dir.children = children;
            self.dirs.get(&parent).unwrap()
        } else {
            dir
        };

        let entry = dir
            .children
            .iter()
            .filter_map(|ino| self.dirs.get(ino))
            .find_map(|dir| (dir.name == name).then_some(&dir.attr))
            .or_else(|| {
                dir.children
                    .iter()
                    .filter_map(|ino| self.files.get(ino))
                    .find_map(|file| (file.name == name).then_some(&file.attr))
            });

        Ok(entry)
    }

    #[allow(
        clippy::cast_possible_wrap,
        clippy::similar_names,
        clippy::too_many_arguments
    )]
    fn setattr_wrapper(
        &mut self,
        ino: u64,
        mode: Option<Mode>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
    ) -> Result<Option<FileAttr>> {
        let Some((path, attr)) = self
            .files
            .get_mut(&ino)
            .map(|f| (&f.path, &mut f.attr))
            .or_else(|| self.dirs.get_mut(&ino).map(|d| (&d.path, &mut d.attr)))
        else {
            return Ok(None);
        };

        if let Some(mode) = mode {
            nix::sys::stat::fchmodat(
                None,
                path,
                nix::sys::stat::Mode::from_bits_truncate(mode.bits()),
                FchmodatFlags::NoFollowSymlink,
            )
            .context("failed changing file mode")?;
        }

        if uid.is_some() || gid.is_some() {
            nix::unistd::chown(path, uid.map(Into::into), gid.map(Into::into))
                .context("failed changing file owner")?;
        }

        if let Some(size) = size {
            if size == 0 {
                nix::unistd::truncate(path, FileHeader::LEN as libc::off_t)
                    .context("failed truncating file")?;
            } else {
                // TODO: last block needs to be re-encrypted after truncation
                // nix::unistd::truncate(&entry.path, size as libc::off_t).unwrap();
                warn!("size changes not supported");
            }
        }

        if atime.is_some() || mtime.is_some() {
            nix::sys::stat::utimensat(
                None,
                path,
                &convert_time_spec(atime),
                &convert_time_spec(mtime),
                UtimensatFlags::NoFollowSymlink,
            )
            .context("failed changing file times")?;
        }

        *attr = file_attr(&path.metadata().unwrap(), attr.size, attr.blocks)
            .context("failed getting fresh file metadata")?;

        Ok(Some(*attr))
    }

    fn mkdir_wrapper(&mut self, parent: u64, name: &OsStr, mode: Mode) -> Result<Option<FileAttr>> {
        let Some(parent) = self.dirs.get_mut(&parent) else {
            return Ok(None);
        };

        let crypt_name = gocryptfs::names::encrypt(&self.master_key, &parent.iv, name)
            .context("failed encrypting dir name")?;
        let path = parent.path.join(crypt_name);

        nix::unistd::mkdir(&path, nix::sys::stat::Mode::from_bits_truncate(mode.bits()))
            .context("failed creating directory")?;

        let dir_iv = gocryptfs::names::create_iv();

        std::fs::write(path.join(gocryptfs::names::DIRIV_NAME), dir_iv)
            .context("failed writing dir IV")?;

        let attr = dir_attr(&path.metadata().context("failed loading dir metadata")?)?;
        parent.children.insert(attr.ino);
        self.dirs.insert(
            attr.ino,
            FuseDir {
                path,
                name: name.to_owned(),
                attr,
                children: FxHashSet::default(),
                iv: dir_iv,
            },
        );

        Ok(Some(attr))
    }

    fn unlink_wrapper(&mut self, parent: u64, name: &OsStr) -> Result<Option<()>> {
        let Some(entry) = self.find_file(parent, name) else {
            return Ok(None);
        };

        fs::remove_file(&entry.path).context("failed removing file")?;

        let entry = entry.attr.ino;
        self.dirs.get_mut(&parent).unwrap().children.remove(&entry);
        self.files.remove(&entry);

        Ok(Some(()))
    }

    fn rmdir_wrapper(&mut self, parent: u64, name: &OsStr) -> Result<Option<()>> {
        let Some(entry) = self.find_dir(parent, name) else {
            return Ok(None);
        };

        fs::remove_dir(&entry.path).context("failed removing directory")?;

        let entry = entry.attr.ino;
        self.dirs.get_mut(&parent).unwrap().children.remove(&entry);

        let entry = self.dirs.remove(&entry).unwrap();
        for child in entry.children {
            self.dirs.remove(&child);
            self.files.remove(&child);
        }

        Ok(Some(()))
    }

    fn rename_wrapper(
        &mut self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
    ) -> Result<Option<()>> {
        let Some(new_iv) = self.dirs.get(&new_parent).map(|p| p.iv) else {
            return Ok(None);
        };

        let ino = if let Some(dir) = self
            .find_dir(parent, name)
            .map(|dir| dir.attr.ino)
            .and_then(|ino| self.dirs.get_mut(&ino))
        {
            let crypt_new_name = gocryptfs::names::encrypt(&self.master_key, &new_iv, new_name)
                .context("failed encrypting new name")?;
            let new_path = dir.path.with_file_name(crypt_new_name);

            fs::rename(&dir.path, &new_path).context("failed renaming directory")?;
            dir.path = new_path;
            dir.name = new_name.to_owned();

            dir.attr.ino
        } else if let Some(file) = self
            .find_file(parent, name)
            .map(|file| file.attr.ino)
            .and_then(|ino| self.files.get_mut(&ino))
        {
            let crypt_new_name = gocryptfs::names::encrypt(&self.master_key, &new_iv, new_name)
                .context("failed encrypting new name")?;
            let new_path = file.path.with_file_name(crypt_new_name);

            fs::rename(&file.path, &new_path).context("failed renaming file")?;
            file.parent = new_parent;
            file.path = new_path;
            file.name = new_name.to_owned();

            file.attr.ino
        } else {
            return Ok(None);
        };

        self.dirs.get_mut(&parent).unwrap().children.remove(&ino);
        self.dirs.get_mut(&new_parent).unwrap().children.insert(ino);

        Ok(Some(()))
    }

    #[allow(clippy::cast_sign_loss)]
    fn open_wrapper(&mut self, ino: u64) -> Result<Option<u64>> {
        let Some(file) = self.files.get(&ino) else {
            return Ok(None);
        };

        let file = File::options()
            .read(true)
            .write(true)
            .open(&file.path)
            .context("failed opening file")?;

        let fd = file.as_raw_fd() as u64;
        self.handles.insert(ino, file);

        Ok(Some(fd))
    }

    #[allow(clippy::cast_precision_loss)]
    fn read_wrapper(&mut self, ino: u64, offset: usize, size: usize) -> Result<Option<Vec<u8>>> {
        ensure!(
            offset % BLOCK_SIZE == 0,
            "offset must be a multiple of the block size (currently)",
        );

        let Some((file, f)) = self.files.get(&ino).zip(self.handles.get(&ino)) else {
            return Ok(None);
        };

        let offset = self.cipher.to_crypt::<BLOCK_SIZE>(offset);
        let size = self.cipher.to_crypt::<BLOCK_SIZE>(size);
        let block_size = BLOCK_SIZE + self.cipher.overhead();

        let real_size = f.metadata()?.size() as usize;
        let mut content = vec![0; size.min(real_size - offset - FileHeader::LEN)];

        f.read_exact_at(&mut content, (FileHeader::LEN + offset) as u64)
            .context("failed reading content")?;

        let plain = self
            .cipher
            .decrypt(&self.master_key, &file.head, &content, offset / block_size)
            .context("failed decrypting content")?;

        Ok(Some(plain))
    }

    fn write_wrapper(&mut self, ino: u64, offset: usize, data: &[u8]) -> Result<Option<u32>> {
        ensure!(
            offset % BLOCK_SIZE == 0,
            "offset must be a multiple of the block size (currently)",
        );

        let Some((file, f)) = self.files.get_mut(&ino).zip(self.handles.get_mut(&ino)) else {
            return Ok(None);
        };

        let crypt_offset = self.cipher.to_crypt::<BLOCK_SIZE>(offset);
        let block_size = BLOCK_SIZE + self.cipher.overhead();

        let mut chunks = data[offset % BLOCK_SIZE..]
            .chunks_exact(BLOCK_SIZE)
            .enumerate();

        for (i, chunk) in &mut chunks {
            let block_offset = crypt_offset / block_size * i;
            let ciphertext = self
                .cipher
                .encrypt(&self.master_key, &file.head, chunk, block_offset)
                .context("failed encrypting content")?;

            f.write_all_at(&ciphertext, (FileHeader::LEN + block_offset) as u64)
                .context("failed writing content")?;
        }

        let blocks = data[offset % BLOCK_SIZE..].len() / BLOCK_SIZE;
        let rem = data[offset % BLOCK_SIZE..].len() % BLOCK_SIZE;

        if rem > 0 {
            trace!(blocks, rem, crypt_offset, block_size; "meep");

            let ciphertext = self
                .cipher
                .encrypt(
                    &self.master_key,
                    &file.head,
                    &data[data.len() - rem..],
                    blocks,
                )
                .context("failed encrypting content")?;

            f.write_all_at(
                &ciphertext,
                (FileHeader::LEN + crypt_offset + block_size * blocks) as u64,
            )
            .context("failed writing content")?;
        }

        let meta = f.metadata().context("failed reading metadata")?;
        let (size, blocks) = self.cipher.to_plain::<BLOCK_SIZE>(meta.size() as usize);

        file.attr = file_attr(&meta, size as u64, blocks as u64)?;

        Ok(Some(data.len() as u32))
    }

    #[allow(clippy::cast_sign_loss)]
    fn create_wrapper(
        &mut self,
        parent: u64,
        name: &OsStr,
        mode: Mode,
    ) -> Result<Option<(FileAttr, u64)>> {
        if let Some(attr) = self.find_file(parent, name).map(|file| file.attr) {
            return self.open_wrapper(attr.ino).map(|fd| Some(attr).zip(fd));
        }

        let Some(dir) = self.dirs.get(&parent) else {
            return Ok(None);
        };

        let crypt_name = gocryptfs::names::encrypt(&self.master_key, &dir.iv, name)
            .context("failed encrypting file name")?;
        let path = dir.path.join(crypt_name);

        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(mode.bits())
            .open(&path)
            .context("failed creating file")?;
        let head = FileHeader::new();

        file.write_all(&head.to_array())
            .context("failed writing file header")?;
        file.flush().context("failed flushing file content")?;

        let attr = file_attr(
            &file.metadata().context("failed reading file metadata")?,
            0,
            0,
        )?;

        self.dirs
            .get_mut(&parent)
            .unwrap()
            .children
            .insert(attr.ino);
        self.files.insert(
            attr.ino,
            FuseFile {
                parent,
                path,
                name: name.to_owned(),
                attr,
                head,
            },
        );

        let fd = file.as_raw_fd() as u64;
        self.handles.insert(attr.ino, file);

        Ok(Some((attr, fd)))
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
impl fuser::Filesystem for Fuse {
    fn init(
        &mut self,
        _req: &fuser::Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), c_int> {
        debug!("init");

        Ok(())
    }

    fn destroy(&mut self) {
        debug!("destroy");

        if let Some(sender) = self.shutdown.take() {
            sender.send(()).ok();
        }
    }

    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        debug!(parent, name:?; "lookup");

        match self.lookup_wrapper(parent, name) {
            Ok(Some(entry)) => reply.entry(&TTL, entry, 0),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "lookup failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn forget(&mut self, _req: &fuser::Request<'_>, ino: u64, nlookup: u64) {
        debug!(ino, nlookup; "forget");

        // Never forget about the root ID, as we rely
        // on it being present at all times.
        if ino == fuser::FUSE_ROOT_ID {
            return;
        }

        self.dirs.remove(&ino);
        self.files.remove(&ino);
    }

    fn batch_forget(&mut self, req: &fuser::Request<'_>, nodes: &[fuser::fuse_forget_one]) {
        debug!(nodes_len = nodes.len(); "batch_forget");

        for node in nodes {
            self.forget(req, node.nodeid, node.nlookup);
        }
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        debug!(ino; "getattr");

        let entry = self
            .dirs
            .get(&ino)
            .map(|dir| &dir.attr)
            .or_else(|| self.files.get(&ino).map(|file| &file.attr));

        if let Some(entry) = entry {
            reply.attr(&TTL, entry);
        } else {
            debug!(ino; "getattr not found");
            reply.error(libc::ENOENT);
        }
    }

    #[allow(clippy::similar_names)]
    fn setattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<std::time::SystemTime>,
        fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: fuser::ReplyAttr,
    ) {
        let mode = mode.map(Mode::from_bits_truncate);
        debug!(ino, mode:?, uid, gid, size, atime:?, mtime:?, ctime:?, fh; "setattr");

        match self.setattr_wrapper(ino, mode, uid, gid, size, atime, mtime) {
            Ok(Some(attr)) => reply.attr(&TTL, &attr),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "setattr failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        debug!(ino; "readlink");
        reply.error(libc::ENOSYS);
    }

    fn mknod(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: fuser::ReplyEntry,
    ) {
        debug!(parent, name:?, mode:? = Mode::from_bits_truncate(mode), umask, rdev; "mknod");
        reply.error(libc::ENOSYS);
    }

    fn mkdir(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        let mode = Mode::from_bits_truncate(mode);
        debug!(parent, name:?, mode:?, umask; "mkdir");

        match self.mkdir_wrapper(parent, name, mode) {
            Ok(Some(attr)) => reply.entry(&TTL, &attr, 0),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "mkdir failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn unlink(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(parent, name:?; "unlink");

        match self.unlink_wrapper(parent, name) {
            Ok(Some(())) => reply.ok(),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "unlink failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn rmdir(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(parent, name:?; "rmdir");

        match self.rmdir_wrapper(parent, name) {
            Ok(Some(())) => reply.ok(),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "rmdir failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn symlink(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: fuser::ReplyEntry,
    ) {
        debug!(parent, link_name:?, target:?; "symlink");
        reply.error(libc::EPERM);
    }

    fn rename(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(parent, name:?, newparent, newname:?, flags; "rename");

        match self.rename_wrapper(parent, name, newparent, newname) {
            Ok(Some(())) => reply.ok(),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "rename failed");
                reply.error(
                    e.downcast::<Errno>()
                        .map(|e| e as c_int)
                        .unwrap_or(libc::EIO),
                );
            }
        }
    }

    fn link(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        debug!(ino, newparent, newname:?; "link");
        reply.error(libc::EPERM);
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        let flags = OpenFlags::from_bits_truncate(flags);
        debug!(ino, flags:?; "open");

        match self.open_wrapper(ino) {
            Ok(Some(fd)) => reply.opened(fd, flags.bits() as u32),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "open failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        debug!(ino, fh, offset, size, flags:? = OpenFlags::from_bits_truncate(flags), lock_owner; "read");

        match self.read_wrapper(ino, offset as usize, size as usize) {
            Ok(Some(data)) => reply.data(&data),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "read failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn write(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        debug!(
            ino,
            fh,
            offset,
            data_len = data.len(),
            write_flags:? = WriteFlags::from_bits_truncate(write_flags),
            flags:? = OpenFlags::from_bits_truncate(flags),
            lock_owner;
            "write",
        );

        match self.write_wrapper(ino, offset as usize, data) {
            Ok(Some(size)) => reply.written(size),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "write failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn flush(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(ino, fh, lock_owner; "flush");

        match self.handles.get_mut(&ino).map(Write::flush).transpose() {
            Ok(Some(())) => reply.ok(),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = e; "flush failed");
                reply.error(libc::EIO);
            }
        }
    }

    fn release(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(ino, fh, flags:? = OpenFlags::from_bits_truncate(flags), lock_owner, flush; "release");

        match self.handles.remove(&ino) {
            Some(mut handle) if flush => match handle.flush() {
                Ok(()) => reply.ok(),
                Err(e) => {
                    error!(error:err = e; "release flush failed");
                    reply.error(libc::EIO);
                }
            },
            Some(_) => reply.ok(),
            None => reply.error(libc::ENOENT),
        }
    }

    fn fsync(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(ino, fh, datasync; "fsync");
        reply.error(libc::ENOSYS);
    }

    fn opendir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        flags: i32,
        reply: fuser::ReplyOpen,
    ) {
        debug!(ino, flags:? = OpenFlags::from_bits_truncate(flags); "opendir");
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        debug!(ino, fh, offset; "readdir");

        let Some(dir) = self.dirs.get(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        let base = &[
            (dir.attr.ino, fuser::FileType::Directory, "."),
            (dir.attr.ino, fuser::FileType::Directory, ".."),
        ];

        let dir = if dir.children.is_empty() {
            match self.read_dir(dir) {
                Ok((dirs, files, children)) => {
                    self.dirs.extend(dirs);
                    self.files.extend(files);
                    let dir = self.dirs.get_mut(&ino).unwrap();
                    dir.children = children;
                    self.dirs.get(&ino).unwrap()
                }
                Err(e) => {
                    error!(error:err = *e; "failed reading directory");
                    reply.error(libc::ENOSYS);
                    return;
                }
            }
        } else {
            dir
        };

        let dirs = dir
            .children
            .iter()
            .filter_map(|ino| self.dirs.get(ino))
            .map(|dir| {
                (
                    dir.attr.ino,
                    fuser::FileType::Directory,
                    dir.name.to_str().unwrap(),
                )
            });

        let files = dir
            .children
            .iter()
            .filter_map(|ino| self.files.get(ino))
            .map(|file| {
                (
                    file.attr.ino,
                    fuser::FileType::RegularFile,
                    file.name.to_str().unwrap(),
                )
            });

        for (i, entry) in base
            .iter()
            .copied()
            .chain(dirs)
            .chain(files)
            .enumerate()
            .skip(offset as usize)
        {
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }

        reply.ok();
    }

    fn readdirplus(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectoryPlus,
    ) {
        debug!(ino, fh, offset; "readdirplus");
        reply.error(libc::ENOSYS);
    }

    fn releasedir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(ino, fh, flags:? = OpenFlags::from_bits_truncate(flags); "releasedir");
        reply.ok();
    }

    fn fsyncdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(ino, fh, datasync; "fsyncdir");
        reply.error(libc::ENOSYS);
    }

    fn statfs(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyStatfs) {
        debug!(ino; "statfs");
        reply.statfs(0, 0, 0, 0, 0, BLOCK_SIZE as u32, 255, 0);
    }

    fn access(&mut self, _req: &fuser::Request<'_>, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        debug!(ino, mask; "access");
        reply.error(libc::ENOSYS);
    }

    fn create(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let mode = Mode::from_bits_truncate(mode);
        let flags = OpenFlags::from_bits_truncate(flags);
        debug!(parent, name:?, mode:?, umask, flags:?; "create");

        match self.create_wrapper(parent, name, mode) {
            Ok(Some((attr, fd))) => reply.created(&TTL, &attr, 0, fd, flags.bits() as u32),
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!(error:err = *e; "create failed");
                reply.error(
                    e.downcast::<Errno>()
                        .map(|e| e as c_int)
                        .unwrap_or(libc::EIO),
                );
            }
        }
    }

    fn getlk(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        reply: fuser::ReplyLock,
    ) {
        debug!(ino, fh, lock_owner, start, end, typ, pid; "getlk");
        reply.error(libc::ENOSYS);
    }

    fn setlk(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(ino, fh, lock_owner, start, end, typ, pid, sleep; "setlk");
        reply.error(libc::ENOSYS);
    }

    fn poll(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        kh: u64,
        events: u32,
        flags: u32,
        reply: fuser::ReplyPoll,
    ) {
        debug!(ino, fh, kh, events, flags; "poll");
        reply.error(libc::ENOSYS);
    }

    fn fallocate(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(ino, fh, offset, length, mode; "fallocate");
        reply.error(libc::ENOSYS);
    }

    fn lseek(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        whence: i32,
        reply: fuser::ReplyLseek,
    ) {
        debug!(ino, fh, offset, whence; "lseek");
        reply.error(libc::ENOSYS);
    }

    fn copy_file_range(
        &mut self,
        _req: &fuser::Request<'_>,
        ino_in: u64,
        fh_in: u64,
        offset_in: i64,
        ino_out: u64,
        fh_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
        reply: fuser::ReplyWrite,
    ) {
        debug!(ino_in, fh_in, offset_in, ino_out, fh_out, offset_out, len, flags; "copy_file_range");
        reply.error(libc::ENOSYS);
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

fn convert_time_spec(time: Option<fuser::TimeOrNow>) -> TimeSpec {
    match time {
        Some(fuser::TimeOrNow::Now) => TimeSpec::UTIME_NOW,
        Some(fuser::TimeOrNow::SpecificTime(t)) => {
            TimeSpec::from_duration(t.duration_since(SystemTime::UNIX_EPOCH).unwrap())
        }
        None => TimeSpec::UTIME_OMIT,
    }
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
