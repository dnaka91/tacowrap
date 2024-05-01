use std::{ffi::OsStr, io::Write, path::Path, time::Duration};

use libc::c_int;
use log::{debug, error};
use nix::errno::Errno;

use super::{Fuse, Mode, OpenFlags, WriteFlags};
use crate::gocryptfs::content::BLOCK_SIZE;

const TTL: Duration = Duration::from_secs(1);

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
            Some(entry) => reply.entry(&TTL, entry, 0),
            None => reply.error(libc::ENOENT),
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
