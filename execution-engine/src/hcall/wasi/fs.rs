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

use std::collections::HashMap;
use wasi_types::{
    Advice, DirCookie, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, IoVec,
    LookupFlags, OpenFlags, Prestat, Rights, Size, Whence,
};

pub(crate) type FileSystemError<T> = Result<T, ErrNo>;

struct INode {
    buffer: Vec<u8>,
}

struct FileTableEntry {
    /// The index into the open file table where the data associated with this
    /// file is stored.
    inode_index: usize,
    /// The current offset of the file descriptor.
    offset: FileSize
}

pub struct FileSystem {
    /// A table of file descriptor table entries.  This is indexed by file
    /// descriptors.  Each file table entry contains an index into the inode
    /// table, pointing to an `INode`, where the data is stored.
    file_table: HashMap<Fd, FileTableEntry>,
    /// The inode table, which points to the actual data associated with a file
    /// and other metadata.  This table is indexed by the indices stored in a
    /// file table entry.
    inode_table: Vec<INode>,
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
            inode_table: Vec::new()
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
        unimplemented!()
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

    pub(crate) fn fd_fdstat_get(&self, fd: &Fd) -> FileSystemError<FdStat> {
        unimplemented!()
    }

    pub(crate) fn fd_fdstat_set_flags(&mut self, fd: &Fd, flags: FdFlags) -> ErrNo {
        unimplemented!()
    }

    pub(crate) fn fd_fdstat_set_rights(
        &mut self,
        fd: &Fd,
        rights_base: Rights,
        rights_inheriting: Rights,
    ) -> ErrNo {
        unimplemented!()
    }

    pub(crate) fn fd_filestat_get(&self, fd: &Fd) -> FileSystemError<FileStat> {
        unimplemented!()
    }

    pub(crate) fn fd_filestat_set_size(&mut self, fd: &Fd, size: FileSize) -> ErrNo {
        unimplemented!()
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
