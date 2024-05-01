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
    stat::{FchmodatFlags, UtimensatFlags},
    time::TimeSpec,
};
use rustc_hash::FxHashSet;

use super::{dir_attr, file_attr, Fuse, FuseDir, FuseFile, Mode};
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
            .find_map(|dir| (dir.name == name).then_some(&dir.attr))
            .or_else(|| {
                dir.children
                    .iter()
                    .filter_map(|ino| self.files.get(ino))
                    .find_map(|file| (file.name == name).then_some(&file.attr))
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

    pub(super) fn mkdir_wrapper(
        &mut self,
        parent: u64,
        name: &OsStr,
        mode: Mode,
    ) -> Result<Option<FileAttr>> {
        let Some(parent) = self.dirs.get_mut(&parent) else {
            return Ok(None);
        };

        let crypt_name = gocryptfs::names::encrypt(&self.master_key, &parent.iv, name)
            .context("failed encrypting dir name")?;
        let path = parent.path.join(crypt_name);

        nix::unistd::mkdir(&path, nix::sys::stat::Mode::from_bits_truncate(mode.bits()))
            .context("failed creating directory")?;

        let dir_iv = gocryptfs::names::create_iv();

        fs::write(path.join(gocryptfs::names::DIRIV_NAME), dir_iv)
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

    pub(super) fn unlink_wrapper(&mut self, parent: u64, name: &OsStr) -> Result<Option<()>> {
        let Some(entry) = self.find_file(parent, name) else {
            return Ok(None);
        };

        fs::remove_file(&entry.path).context("failed removing file")?;

        let entry = entry.attr.ino;
        self.dirs.get_mut(&parent).unwrap().children.remove(&entry);
        self.files.remove(&entry);

        Ok(Some(()))
    }

    pub(super) fn rmdir_wrapper(&mut self, parent: u64, name: &OsStr) -> Result<Option<()>> {
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

    pub(super) fn rename_wrapper(
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
    pub(super) fn open_wrapper(&mut self, ino: u64) -> Result<Option<u64>> {
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
        let path = dir.path.join(crypt_name);

        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(mode.bits())
            .open(&path)
            .context("failed creating file")?;

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
        Some(fuser::TimeOrNow::SpecificTime(t)) => {
            TimeSpec::from_duration(t.duration_since(SystemTime::UNIX_EPOCH).unwrap())
        }
        None => TimeSpec::UTIME_OMIT,
    }
}
