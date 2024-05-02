use std::{
    ffi::OsStr,
    fs::{self, File},
    os::unix::prelude::*,
    time::SystemTime,
};

use anyhow::{ensure, Context, Result};
use fuser::FileAttr;
use log::warn;
use nix::sys::{
    stat::{FchmodatFlags, Mode, UtimensatFlags},
    time::TimeSpec,
};
use rustc_hash::FxHashSet;

use super::{dir_attr, file_attr, Fuse, FuseDir, FuseFile};
use crate::gocryptfs::{
    self,
    content::{FileHeader, BLOCK_SIZE},
};

impl Fuse {
    pub(super) fn lookup_wrapper(&mut self, parent: u64, name: &OsStr) -> Option<&FileAttr> {
        let dir = self.dirs.get(&parent)?;

        dir.children
            .iter()
            .filter_map(|ino| self.dirs.get(ino))
            .find_map(|dir| (dir.plain_name == name).then_some(&dir.attr))
            .or_else(|| {
                dir.children
                    .iter()
                    .filter_map(|ino| self.files.get(ino))
                    .find_map(|file| (file.plain_name == name).then_some(&file.attr))
            })
    }

    #[allow(
        clippy::cast_possible_wrap,
        clippy::similar_names,
        clippy::too_many_arguments
    )]
    pub(super) fn setattr_wrapper(
        &mut self,
        ino: u64,
        mode: Option<Mode>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
    ) -> Result<Option<FileAttr>> {
        let Some(path) = self
            .files
            .get(&ino)
            .map(|f| self.file_path(f))
            .or_else(|| self.dirs.get(&ino).map(|d| self.dir_path(d)))
        else {
            return Ok(None);
        };

        if let Some(mode) = mode {
            nix::sys::stat::fchmodat(None, &path, mode, FchmodatFlags::NoFollowSymlink)
                .context("failed changing file mode")?;
        }

        if uid.is_some() || gid.is_some() {
            nix::unistd::chown(&path, uid.map(Into::into), gid.map(Into::into))
                .context("failed changing file owner")?;
        }

        if let Some(size) = size {
            if size == 0 {
                nix::unistd::truncate(&path, FileHeader::LEN as libc::off_t)
                    .context("failed truncating file")?;
            } else {
                // TODO: last block needs to be re-encrypted after truncation
                // nix::unistd::truncate(&entry.path, size as libc::off_t);
                warn!("size changes not supported");
            }
        }

        if atime.is_some() || mtime.is_some() {
            nix::sys::stat::utimensat(
                None,
                &path,
                &convert_time_spec(atime),
                &convert_time_spec(mtime),
                UtimensatFlags::NoFollowSymlink,
            )
            .context("failed changing file times")?;
        }

        let meta = path.metadata().context("failed reading metadata")?;

        let attr = if let Some(file) = self.files.get_mut(&ino) {
            let (size, blocks) = self
                .cipher
                .to_plain::<BLOCK_SIZE>(meta.size() as usize - FileHeader::LEN);
            file.attr = file_attr(&meta, (size - FileHeader::LEN) as u64, blocks as u64)
                .context("failed getting fresh file metadata")?;
            file.attr
        } else if let Some(dir) = self.dirs.get_mut(&ino) {
            dir.attr = dir_attr(&meta).context("failed getting fresh directory metadata")?;
            dir.attr
        } else {
            unreachable!()
        };

        Ok(Some(attr))
    }

    pub(super) fn mkdir_wrapper(
        &mut self,
        parent: u64,
        name: &OsStr,
        mode: Mode,
    ) -> Result<Option<FileAttr>> {
        let Some(dir) = self.dirs.get(&parent) else {
            return Ok(None);
        };

        let crypt_name = gocryptfs::names::encrypt(&self.master_key, &dir.iv, name)
            .context("failed encrypting dir name")?;
        let path = self.dir_path(dir).join(&crypt_name);

        nix::unistd::mkdir(&path, mode).context("failed creating directory")?;

        let dir_iv = gocryptfs::names::create_iv();

        fs::write(path.join(gocryptfs::names::DIRIV_NAME), dir_iv)
            .context("failed writing dir IV")?;

        let attr = dir_attr(&path.metadata().context("failed loading dir metadata")?)?;

        if let Some(parent) = self.dirs.get_mut(&parent) {
            parent.children.insert(attr.ino);
        }

        self.dirs.insert(
            attr.ino,
            FuseDir {
                parent,
                crypt_name,
                plain_name: name.to_owned(),
                attr,
                children: FxHashSet::default(),
                iv: dir_iv,
            },
        );

        Ok(Some(attr))
    }

    pub(super) fn unlink_wrapper(&mut self, parent: u64, name: &OsStr) -> Result<Option<()>> {
        let Some(entry) = self.find_file(parent, name) else {
            return Ok(None);
        };

        fs::remove_file(self.file_path(entry)).context("failed removing file")?;
        let entry = entry.attr.ino;

        if let Some(parent) = self.dirs.get_mut(&parent) {
            parent.children.remove(&entry);
        }
        self.files.remove(&entry);

        Ok(Some(()))
    }

    pub(super) fn rmdir_wrapper(&mut self, parent: u64, name: &OsStr) -> Result<Option<()>> {
        let Some(entry) = self.find_dir(parent, name) else {
            return Ok(None);
        };

        fs::remove_dir(self.dir_path(entry)).context("failed removing directory")?;
        let entry = entry.attr.ino;

        if let Some(parent) = self.dirs.get_mut(&parent) {
            parent.children.remove(&entry);
        }

        if let Some(entry) = self.dirs.remove(&entry) {
            for child in entry.children {
                self.dirs.remove(&child);
                self.files.remove(&child);
            }
        }

        Ok(Some(()))
    }

    pub(super) fn rename_wrapper(
        &mut self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
    ) -> Result<Option<()>> {
        let Some((new_iv, new_path)) = self.dirs.get(&new_parent).map(|p| (p.iv, self.dir_path(p)))
        else {
            return Ok(None);
        };

        let ino = if let Some((dir, dir_path)) = self
            .find_dir(parent, name)
            .map(|dir| (dir.attr.ino, self.dir_path(dir)))
            .and_then(|(ino, path)| self.dirs.get_mut(&ino).zip(Some(path)))
        {
            let new_crypt_name = gocryptfs::names::encrypt(&self.master_key, &new_iv, new_name)
                .context("failed encrypting new name")?;

            fs::rename(dir_path, new_path.join(&new_crypt_name))
                .context("failed renaming directory")?;

            dir.parent = new_parent;
            dir.crypt_name = new_crypt_name;
            dir.plain_name = new_name.to_owned();

            dir.attr.ino
        } else if let Some((file, file_path)) = self
            .find_file(parent, name)
            .map(|file| (file.attr.ino, self.file_path(file)))
            .and_then(|(ino, path)| self.files.get_mut(&ino).zip(Some(path)))
        {
            let new_crypt_name = gocryptfs::names::encrypt(&self.master_key, &new_iv, new_name)
                .context("failed encrypting new name")?;

            fs::rename(file_path, new_path.join(&new_crypt_name))
                .context("failed renaming file")?;

            file.parent = new_parent;
            file.crypt_name = new_crypt_name;
            file.plain_name = new_name.to_owned();

            file.attr.ino
        } else {
            return Ok(None);
        };

        if let Some(parent) = self.dirs.get_mut(&parent) {
            parent.children.remove(&ino);
        }
        if let Some(new_parent) = self.dirs.get_mut(&new_parent) {
            new_parent.children.insert(ino);
        }

        Ok(Some(()))
    }

    #[allow(clippy::cast_sign_loss)]
    pub(super) fn open_wrapper(&mut self, ino: u64) -> Result<Option<u64>> {
        let Some(file) = self.files.get(&ino) else {
            return Ok(None);
        };

        let file = File::options()
            .read(true)
            .write(true)
            .open(self.file_path(file))
            .context("failed opening file")?;

        let fd = file.as_raw_fd() as u64;
        self.handles.insert(ino, file);

        Ok(Some(fd))
    }

    #[allow(clippy::cast_precision_loss)]
    pub(super) fn read_wrapper(
        &mut self,
        ino: u64,
        offset: usize,
        size: usize,
    ) -> Result<Option<Vec<u8>>> {
        ensure!(
            offset % BLOCK_SIZE == 0,
            "offset must be a multiple of the block size (currently)",
        );

        let Some((file, f)) = self.files.get(&ino).zip(self.handles.get(&ino)) else {
            return Ok(None);
        };

        let Some(head) = &file.head else {
            return Ok(Some(vec![]));
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
            .decrypt(&self.master_key, head, &content, offset / block_size)
            .context("failed decrypting content")?;

        Ok(Some(plain))
    }

    pub(super) fn write_wrapper(
        &mut self,
        ino: u64,
        offset: usize,
        data: &[u8],
    ) -> Result<Option<u32>> {
        ensure!(
            offset % BLOCK_SIZE == 0,
            "offset must be a multiple of the block size (currently)",
        );

        let Some((file, f)) = self.files.get_mut(&ino).zip(self.handles.get_mut(&ino)) else {
            return Ok(None);
        };

        let head = match &file.head {
            Some(head) => head,
            None => {
                let head = FileHeader::new();
                f.write_all_at(&head.to_array(), 0)
                    .context("failed writing header")?;

                file.head.insert(head)
            }
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
                .encrypt(&self.master_key, head, chunk, block_offset)
                .context("failed encrypting content")?;

            f.write_all_at(&ciphertext, (FileHeader::LEN + block_offset) as u64)
                .context("failed writing content")?;
        }

        let blocks = data[offset % BLOCK_SIZE..].len() / BLOCK_SIZE;
        let rem = data[offset % BLOCK_SIZE..].len() % BLOCK_SIZE;

        if rem > 0 {
            let ciphertext = self
                .cipher
                .encrypt(&self.master_key, head, &data[data.len() - rem..], blocks)
                .context("failed encrypting content")?;

            f.write_all_at(
                &ciphertext,
                (FileHeader::LEN + crypt_offset + block_size * blocks) as u64,
            )
            .context("failed writing content")?;
        }

        let meta = f.metadata().context("failed reading metadata")?;
        let (size, blocks) = self
            .cipher
            .to_plain::<BLOCK_SIZE>(meta.size() as usize - FileHeader::LEN);

        file.attr = file_attr(&meta, (size - FileHeader::LEN) as u64, blocks as u64)?;

        Ok(Some(data.len() as u32))
    }

    #[allow(clippy::cast_sign_loss)]
    pub(super) fn create_wrapper(
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

        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(mode.bits())
            .open(self.dir_path(dir).join(&crypt_name))
            .context("failed creating file")?;

        let attr = file_attr(
            &file.metadata().context("failed reading file metadata")?,
            0,
            0,
        )?;

        if let Some(parent) = self.dirs.get_mut(&parent) {
            parent.children.insert(attr.ino);
        }

        self.files.insert(
            attr.ino,
            FuseFile {
                parent,
                crypt_name,
                plain_name: name.to_owned(),
                attr,
                head: None,
            },
        );

        let fd = file.as_raw_fd() as u64;
        self.handles.insert(attr.ino, file);

        Ok(Some((attr, fd)))
    }
}

fn convert_time_spec(time: Option<fuser::TimeOrNow>) -> TimeSpec {
    match time {
        Some(fuser::TimeOrNow::Now) => TimeSpec::UTIME_NOW,
        Some(fuser::TimeOrNow::SpecificTime(t)) => TimeSpec::from_duration(
            t.duration_since(SystemTime::UNIX_EPOCH)
                .expect("valid post-epoch timestamp"),
        ),
        None => TimeSpec::UTIME_OMIT,
    }
}
