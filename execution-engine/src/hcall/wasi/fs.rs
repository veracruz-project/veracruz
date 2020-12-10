//! A synthetic filesystem.
//!
//! This file defines a simple filesystem with named directories and files.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::{string::String, collections::HashMap};
use wasi_types::{
    Advice, DirCookie, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, IoVec,
    LookupFlags, OpenFlags, Prestat, Rights, Size, Whence, Inode
};

pub(crate) type FileSystemError<T> = Result<T, ErrNo>;

struct InodeImpl {
    /// The status of this file.
    file_stat: FileStat,
    /// The content of the file in bytes.
    buffer: Vec<u8>,
}

/// Each file table entry contains an index into the inode
/// table, pointing to an `InodeImpl`, where the static file data is stored. 
struct FileTableEntry {
    /// The index to `inode_table` in FileSystem.
    inode : Inode,
    /// Metadata for the file descriptor.
    fd_stat : FdStat,
    /// The current offset of the file descriptor.
    offset: FileSize,
}

pub struct FileSystem {
    /// A table of file descriptor table entries.  This is indexed by file
    /// descriptors.  
    file_table: HashMap<Fd, FileTableEntry>,
    /// The structure of the file system.
    /// NOTE: this will evolve to a full directory (tree) structure.
    path_table: HashMap<String, Inode>,
    /// The inode table, which points to the actual data associated with a file
    /// and other metadata.  This table is indexed by the Inode.
    inode_table: HashMap<Inode, InodeImpl>,
}

impl FileSystem {
    ////////////////////////////////////////////////////////////////////////////
    // Creating filesystems.
    ////////////////////////////////////////////////////////////////////////////

    /// Creates a new, empty filesystem.
    ///
    /// TODO: the file descriptors 0, 1, and 2 are pre-allocated for stdin and
    /// similar.  Rust programs are going to expect that this is true, so we
    /// need to preallocate some files corresponding to those, here.
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            file_table: HashMap::new(),
            path_table: HashMap::new(),
            inode_table: HashMap::new(),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Operations on the filesystem.
    ////////////////////////////////////////////////////////////////////////////

    /// Implements the `fd_close` operation on the filesystem, which closes a
    /// file descriptor.  Returns:
    ///
    /// 1. `ErrNo::BadF` if `fd` is not a current file-descriptor.  In this
    ///    case there are no changes to the underlying filesystem.
    /// 2. `ErrNo::Success` if `fd` is a current file-descriptor.  In this case,
    ///    the file-descriptor is closed and no longer a valid file-descriptor.
    pub(crate) fn fd_close(&mut self, fd: &Fd) -> ErrNo {
        match self.file_descriptors.remove(fd) {
            Some(_) => ErrNo::Success,
            None => ErrNo:BadF,
        }
    }

    pub(crate) fn fd_advise(
        &mut self,
        fd: &Fd,
        offset: FileSize,
        len: FileSize,
        advice: Advice,
    ) -> ErrNo {
        unimplemented!()
    }

    pub(crate) fn fd_allocate(&mut self, fd: &Fd, offset: FileSize, len: FileSize) -> ErrNo {
        unimplemented!()
    }

    /// Return a copy of the status of the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_get(&self, fd: &Fd) -> FileSystemError<FdStat> {
        self.file_table.get(fd).map(|FileTableEntry{ file_stat, .. }| {
            fd_stat.clone()
        })
        .ok_or(ErrNo::BadF) 
    }

    /// Change the flag associated with the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_set_flags(&mut self, fd: &Fd, flags: FdFlags) -> ErrNo {
        self.file_descriptors.get_mut(fd).map(|FileTableEntry{ fd_stat, .. }| {
            fd_stat.flags = flags;
            ErrNo::Success
        })
        .unwrap_or(ErrNo::BadF) 
    }

    /// Change the right associated with the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_set_rights(
        &mut self,
        fd: &Fd,
        rights_base: Rights,
        rights_inheriting: Rights,
    ) -> ErrNo {
        self.file_table.get_mut(fd).map(|FileTableEntry{ fd_stat, .. }| {
            fd_stat.rights_base = rights_base;
            ErrNo::Success
        })
        .unwrap_or(ErrNo::BadF) 
    }

    /// Return a copy of the status of the open file pointed by the file descriptor, `fd`.
    pub(crate) fn fd_filestat_get(&self, fd: &Fd) -> FileSystemError<FileStat> {

        let inode = match self.file_table.get(fd) {
            Some(FileTableEntry{ inode, .. }) => inode,
            None => return ErrNo::BadF,
        };

        self.inode_table.get_mut(inode).map(|InodeImpl{file_stat, .. }| {
            file_stat.clone()
        })
        .ok_or(ErrNo::BadF) 
    }

    /// Change the size of the open file pointed by the file descriptor, `fd`. The extra bypes are
    /// filled with ZERO.
    pub(crate) fn fd_filestat_set_size(&mut self, fd: &Fd, size: FileSize) -> ErrNo {
        let inode = match self.file_table.get(fd) {
            Some(FileTableEntry{ inode, .. }) => inode,
            None => return ErrNo::BadF,
        };

        self.inode_table.get_mut(inode).map(|InodeImpl{file_stat, buffer}| {
            file_stat.file_size = size;
            buffer.resize(size,0);
            ErrNo::Success
        })
        .unwrap_or(ErrNo::BadF) 
    }

    pub(crate) fn fd_pread(
        &mut self,
        fd: &Fd,
        iovs: IoVec,
        offset: &FileSize,
    ) -> FileSystemError<Size> {
        unimplemented!()
    }

    pub(crate) fn fd_prestat_get(&mut self, fd: &Fd) -> FileSystemError<Prestat> {
        unimplemented!()
    }

    pub(crate) fn fd_prestat_dir_name(&mut self, fd: &Fd) -> FileSystemError<String> {
        unimplemented!()
    }

    pub(crate) fn fd_pwrite(
        &mut self,
        fd: &Fd,
        ciovec: Vec<IoVec>,
        offset: FileSize,
    ) -> FileSystemError<Size> {
        unimplemented!()
    }

    pub(crate) fn fd_read(&mut self, fd: &Fd, iovec: Vec<IoVec>) -> FileSystemError<Size> {
        unimplemented!()
    }

    pub(crate) fn fd_readdir(
        &mut self,
        fd: &Fd,
        cookie: DirCookie,
    ) -> FileSystemError<Vec<String>> {
        unimplemented!()
    }

    /// Atomically renumbers the `old_fd` to the `new_fd`.  Note that as
    /// Chihuahua is single-threaded this is atomic from the WASM program's
    /// point of view.
    pub(crate) fn fd_renumber(&mut self, old_fd: &Fd, new_fd: Fd) -> ErrNo {
        if let Some(entry) = self.file_table.get(old_fd) && self.file_table.get(new_fd).is_none() {
            self.file_table.insert(new_fd, entry.clone());
            self.file_table.remove(old_fd);
            ErrNo::Success
        } else {
            ErrNo::BadF
        }
    }

    pub(crate) fn fd_seek(
        &mut self,
        offset: FileDelta,
        whence: Whence,
    ) -> FileSystemError<FileSize> {
        unimplemented!()
    }

    /// Returns the current offset associated with the file descriptor.
    pub(crate) fn fd_tell(&self, fd: &Fd) -> FileSystemError<&FileSize> {
        if let Some(entry) = self.file_table.get::<FileTableEntry>(fd) {
            Ok(entry.offset)
        } else {
            Err(ErrNo::BadF)
        }
    }

    pub(crate) fn fd_write(&mut self, fd: &Fd, iovs: Vec<IoVec>) -> FileSystemError<Size> {
        unimplemented!()
    }

    pub(crate) fn path_create_directory(&mut self, fd: &Fd, path: String) -> ErrNo {
        unimplemented!()
    }

    pub(crate) fn path_filestat_get(
        &mut self,
        fd: &Fd,
        flags: LookupFlags,
        path: String,
    ) -> FileSystemError<FileStat> {
        unimplemented!()
    }

    pub(crate) fn path_open(
        &mut self,
        fd: &Fd,
        dirflags: LookupFlags,
        path: String,
        oflags: OpenFlags,
        fs_rights_base: Rights,
        fs_rights_inheriting: Rights,
        fdflags: FdFlags,
    ) -> FileSystemError<Fd> {
        unimplemented!()
    }

    pub(crate) fn path_remove_directory(&mut self, fd: &Fd, path: String) -> ErrNo {
        unimplemented!()
    }

    pub(crate) fn path_rename(
        &mut self,
        old_fd: &Fd,
        old_path: String,
        new_fd: &Fd,
        new_path: String,
    ) -> ErrNo {
        unimplemented!()
    }
}
