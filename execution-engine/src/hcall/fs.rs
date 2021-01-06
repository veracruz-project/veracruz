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

use std::{
    collections::HashMap,
    convert::TryFrom,
    path::{Path, PathBuf},
    string::String,
};
use wasi_types::{
    Advice, DirCookie, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, Inode,
    LookupFlags, OpenFlags, Prestat, Rights, Size, Whence,
};

////////////////////////////////////////////////////////////////////////////////
// Filesystem errors.
////////////////////////////////////////////////////////////////////////////////

/// Filesystem errors either return a result of type `T` or a defined error
/// code.  The return code `ErrNo::Success` is implicit if `Ok(result)` is ever
/// returned from a filesystem function.  The result `Err(ErrNo::Success)`
/// should never be returned.
pub(crate) type FileSystemError<T> = Result<T, ErrNo>;

////////////////////////////////////////////////////////////////////////////////
// INodes.
////////////////////////////////////////////////////////////////////////////////

/// INodes wrap the actual raw file data, and associate meta-data with that raw
/// data buffer.
#[derive(Clone)]
struct InodeImpl {
    /// The status of this file.
    file_stat: FileStat,
    /// The content of the file in bytes.  NOTE: the buffer.size() *must* match
    /// with `file_stat.file_size`.
    raw_file_data: Vec<u8>,
}

impl InodeImpl {
    /// Returns `true` iff the size of the inode's raw data buffer matches the
    /// length stored in the file stat structure.
    ///
    /// TODO: may panic if `usize` and `u64` bitwidths are different!  This
    /// should probably be checked using a static assertion somewhere
    /// once-and-for-all to make sure Veracruz is used only on platforms where
    /// `sizeof::<usize>()` returns `8`, as this assumption is baked-in to the
    /// Veracruz source code in a few different places.
    #[inline]
    pub(crate) fn valid(&self) -> bool {
        self.raw_file_data.len()
            == usize::try_from(self.file_stat.file_size)
                .expect("The bitwidth of the Rust `usize` type is not 64-bits.")
    }

    /// Returns the file stat structure associated with this inode.
    #[inline]
    pub(crate) fn file_stat(&self) -> &FileStat {
        &self.file_stat
    }

    /// Returns the raw file data associated with this inode.
    #[inline]
    pub(crate) fn raw_file_data(&self) -> &Vec<u8> {
        &self.raw_file_data
    }
}

////////////////////////////////////////////////////////////////////////////////
// File-table entries.
////////////////////////////////////////////////////////////////////////////////

/// Each file table entry contains an index into the inode table, pointing to an
/// `InodeImpl`, where the static file data is stored.
#[derive(Clone)]
struct FileTableEntry {
    /// The index to `inode_table` in FileSystem.
    inode: Inode,
    /// Metadata for the file descriptor.
    fd_stat: FdStat,
    /// The current offset of the file descriptor.
    offset: FileSize,
    /// Advice on how regions of the file are to be used.
    advice: Vec<(FileSize, FileSize, Advice)>,
}

impl FileTableEntry {
    /// Returns the inode associated with the file table entry.
    #[inline]
    pub fn inode(&self) -> &Inode {
        &self.inode
    }

    /// Returns the FD stat structure associated with the file table entry.
    #[inline]
    pub fn fd_stat(&self) -> &FdStat {
        &self.fd_stat
    }

    /// Returns the current file (seek) offset associated with the file table
    /// entry.
    #[inline]
    pub fn offset(&self) -> &FileSize {
        &self.offset
    }

    /// Returns the regions of advice applied to this file.
    #[inline]
    pub fn advice(&self) -> &Vec<(FileSize, FileSize, Advice)> {
        &self.advice
    }
}

////////////////////////////////////////////////////////////////////////////////
// Filesystems.
////////////////////////////////////////////////////////////////////////////////

/// The filesystem proper, which collects together various tables and bits of
/// meta-data.
#[derive(Clone)]
pub struct FileSystem {
    /// A table of file descriptor table entries.  This is indexed by file
    /// descriptors.  
    file_table: HashMap<Fd, FileTableEntry>,
    /// The structure of the file system.
    ///
    /// NOTE: This is a flat map from files to inodes for now.  It will evolve
    /// to a full directory (tree) structure.
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
    // XXX: remove and replace with wasi-functionality
    ////////////////////////////////////////////////////////////////////////////

    pub(crate) fn file_exists<U>(&self, path: U) -> bool
    where
        U: AsRef<Path>,
    {
        let path = path.as_ref();

        unimplemented!()
    }

    pub(crate) fn write_file(&mut self, _path: &PathBuf, _data: Vec<u8>) {
        unimplemented!()
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
        match self.file_table.remove(fd) {
            Some(_) => ErrNo::Success,
            None => ErrNo::BadF,
        }
    }

    /// Allows the programmer to declare how they intend to use various parts of
    /// a file to the runtime.  At the moment, we just keep this information,
    /// and don't yet act on it (but may need to start doing for for e.g.
    /// streaming).
    pub(crate) fn fd_advise(
        &mut self,
        fd: &Fd,
        offset: FileSize,
        len: FileSize,
        adv: Advice,
    ) -> ErrNo {
        if let Some(entry) = self.file_table.get_mut(fd) {
            entry.advice.push((offset, len, adv));
            return ErrNo::Success;
        } else {
            return ErrNo::BadF;
        }
    }

    /// Return a copy of the status of the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_get(&self, fd: &Fd) -> FileSystemError<FdStat> {
        self.file_table
            .get(fd)
            .map(|FileTableEntry { fd_stat, .. }| fd_stat.clone())
            .ok_or(ErrNo::BadF)
    }

    /// Change the flag associated with the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_set_flags(&mut self, fd: &Fd, flags: FdFlags) -> ErrNo {
        self.file_table
            .get_mut(fd)
            .map(|FileTableEntry { mut fd_stat, .. }| {
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
        self.file_table
            .get_mut(fd)
            .map(|FileTableEntry { mut fd_stat, .. }| {
                fd_stat.rights_base = rights_base;
                fd_stat.rights_inheriting = rights_inheriting;
                ErrNo::Success
            })
            .unwrap_or(ErrNo::BadF)
    }

    /// Return a copy of the status of the open file pointed by the file descriptor, `fd`.
    pub(crate) fn fd_filestat_get(&self, fd: &Fd) -> FileSystemError<FileStat> {
        let inode = self
            .file_table
            .get(fd)
            .map(|fte| fte.inode())
            .ok_or(ErrNo::BadF)?;

        self.inode_table
            .get(inode)
            .map(|InodeImpl { file_stat, .. }| file_stat.clone())
            .ok_or(ErrNo::BadF)
    }

    /// Change the size of the open file pointed by the file descriptor, `fd`. The extra bypes are
    /// filled with ZERO.
    pub(crate) fn fd_filestat_set_size(&mut self, fd: &Fd, size: FileSize) -> ErrNo {
        let inode = match self.file_table.get(fd) {
            Some(FileTableEntry { inode, .. }) => inode,
            None => return ErrNo::BadF,
        };

        if let Some(inode) = self.inode_table.get_mut(inode) {
            inode.file_stat.file_size = size;
            inode.raw_file_data.resize(size as usize, 0);
            return ErrNo::Success;
        } else {
            return ErrNo::BadF;
        }
    }

    /// This is a rust-style base implementation for fd_pread.
    /// The actual WASI spec, requires, after `fd`, an extra parameter of type IoVec,
    /// to which the content should be written.
    /// Also the WASI requires the function returns the number of byte read.
    /// However, the implementation of WASI spec of fd_pread depends on
    /// how a particular execution engine handles the memory.
    /// That is, different engines provide different API to interact the linear memory
    /// space of WASM.
    pub(crate) fn fd_pread_base(
        &mut self,
        fd: &Fd,
        buffer_len: usize,
        offset: &FileSize,
    ) -> FileSystemError<Vec<u8>> {
        let inode = self
            .file_table
            .get(fd)
            .map(|FileTableEntry { inode, .. }| inode)
            .ok_or(ErrNo::BadF)?;

        self.inode_table
            .get(inode)
            .map(
                |InodeImpl {
                     raw_file_data: buffer,
                     ..
                 }| {
                    // TODO: It should be safe to convert a u64 to usize.
                    let usize_offset = *offset as usize;
                    let (_, to_read) = buffer.split_at(if usize_offset < buffer.len() {
                        usize_offset
                    } else {
                        buffer.len()
                    });
                    let segment = vec![usize_offset, buffer_len, to_read.len()];
                    let read_length = segment.iter().min().unwrap_or(&0);
                    let (rst, _) = to_read.split_at(*read_length);
                    rst.to_vec()
                },
            )
            .ok_or(ErrNo::BadF)
    }

    pub(crate) fn fd_prestat_get(&mut self, _fd: &Fd) -> FileSystemError<Prestat> {
        unimplemented!()
    }

    pub(crate) fn fd_prestat_dir_name(&mut self, _fd: &Fd) -> FileSystemError<String> {
        unimplemented!()
    }

    /// This is a rust-style base implementation for fd_pwrite_base.
    /// The actual WASI spec, requires that `ciovec` is of type Vec<IoVec>.
    /// However, the implementation of WASI spec of fd_pread depends on
    /// how a particular execution engine handles the memory.
    /// That is, different engines provide different API to interact the linear memory
    /// space of WASM.
    pub(crate) fn fd_pwrite_base(
        &mut self,
        fd: &Fd,
        mut buf: Vec<u8>,
        offset: FileSize,
    ) -> FileSystemError<Size> {
        let inode = self
            .file_table
            .get(fd)
            .map(|FileTableEntry { inode, .. }| inode)
            .ok_or(ErrNo::BadF)?;

        if let Some(inode) = self.inode_table.get_mut(inode) {
            let rst = buf.len();
            inode.raw_file_data.remove(offset as usize);
            inode.raw_file_data.append(&mut buf);
            inode.file_stat.file_size += rst as u64;
            return Ok(rst as Size);
        } else {
            return Err(ErrNo::BadF);
        }
    }

    pub(crate) fn fd_read_base(&mut self, fd: &Fd, len: usize) -> FileSystemError<Vec<u8>> {
        let offset = if let Some(entry) = self.file_table.get(fd) {
            entry.offset
        } else {
            return Err(ErrNo::BadF);
        };

        let rst = self.fd_pread_base(fd, len, &offset)?;
        self.fd_seek(fd, rst.len() as i64, Whence::Current)?;
        Ok(rst)
    }

    pub(crate) fn fd_readdir(
        &mut self,
        _fd: &Fd,
        _cookie: DirCookie,
    ) -> FileSystemError<Vec<String>> {
        unimplemented!()
    }

    /// Atomically renumbers the `old_fd` to the `new_fd`.  Note that as
    /// Chihuahua is single-threaded this is atomic from the WASM program's
    /// point of view.
    pub(crate) fn fd_renumber(&mut self, old_fd: &Fd, new_fd: Fd) -> ErrNo {
        if let Some(entry) = self.file_table.get(old_fd) {
            if self.file_table.get(&new_fd).is_none() {
                let entry = entry.clone();
                self.file_table.insert(new_fd, entry);
                self.file_table.remove(old_fd);
                return ErrNo::Success;
            }
        }
        ErrNo::BadF
    }

    pub(crate) fn fd_seek(
        &mut self,
        fd: &Fd,
        offset: FileDelta,
        whence: Whence,
    ) -> FileSystemError<FileSize> {
        let (inode, cur_file_offset) = match self.file_table.get(fd) {
            // Use temporary variable `o` to reduce the ambiguity with the function parameter `offset`.
            Some(FileTableEntry {
                inode, offset: o, ..
            }) => (inode, o),
            None => return Err(ErrNo::BadF),
        };

        let file_size = match self.inode_table.get(inode) {
            Some(InodeImpl { file_stat, .. }) => file_stat.file_size,
            None => return Err(ErrNo::BadF),
        };

        let new_base_offset = match whence {
            Whence::Current => *cur_file_offset,
            Whence::End => file_size,
            Whence::Start => 0,
        };

        // NOTE: Ensure the computation does not overflow.
        let new_offset: FileSize = if offset >= 0 {
            // It is safe to convert a positive i64 to u64.
            let t_offset = new_base_offset + (offset.abs() as u64);
            if t_offset >= file_size {
                return Err(ErrNo::Inval);
            }
            t_offset
        } else {
            // It is safe to convert a positive i64 to u64.
            if (offset.abs() as u64) > new_base_offset {
                return Err(ErrNo::Inval);
            }
            new_base_offset - (offset.abs() as u64)
        };

        // Update the offset
        if let Some(entry) = self.file_table.get_mut(fd) {
            entry.offset = new_offset;
        } else {
            return Err(ErrNo::BadF);
        };

        Ok(new_offset)
    }

    /// Returns the current offset associated with the file descriptor.
    pub(crate) fn fd_tell(&self, fd: &Fd) -> FileSystemError<&FileSize> {
        if let Some(entry) = self.file_table.get(fd) {
            Ok(&entry.offset)
        } else {
            Err(ErrNo::BadF)
        }
    }

    pub(crate) fn fd_write_base(&mut self, fd: &Fd, buf: Vec<u8>) -> FileSystemError<Size> {
        let offset = if let Some(entry) = self.file_table.get(fd) {
            entry.offset
        } else {
            return Err(ErrNo::BadF);
        };

        let rst = self.fd_pwrite_base(fd, buf, offset)?;
        self.fd_seek(fd, rst as i64, Whence::Current)?;
        Ok(rst)
    }

    pub(crate) fn path_create_directory(&mut self, _fd: &Fd, _path: String) -> ErrNo {
        unimplemented!()
    }

    pub(crate) fn path_filestat_get(
        &mut self,
        _fd: &Fd,
        _flags: LookupFlags,
        path: String,
    ) -> FileSystemError<FileStat> {
        let inode = self.path_table.get(&path).ok_or(ErrNo::NoEnt)?.clone();
        self.inode_table
            .get(&inode)
            .map(|InodeImpl { file_stat, .. }| file_stat.clone())
            .ok_or(ErrNo::BadF)
    }

    /// Open a file or directory.
    /// TODO: It provides the minimum functionality of opening a file.
    ///       Finish the rest functionality required the WASI spec.
    pub(crate) fn path_open(
        &mut self,
        _fd: &Fd,
        _dirflags: LookupFlags,
        path: String,
        _oflags: OpenFlags,
        rights_base: Rights,
        rights_inheriting: Rights,
        flags: FdFlags,
    ) -> FileSystemError<Fd> {
        let inode = self.path_table.get(&path).ok_or(ErrNo::NoEnt)?.clone();
        // TODO: It is an insecure implementation of choosing a new FD.
        //       The new FD should be choisen randomly.
        // NOTE: the FD 0,1 and 2 are reserved to in out err.
        let next_fd = self
            .file_table
            .keys()
            .max()
            .map(|Fd(fd_num)| Fd(fd_num + 1))
            .unwrap_or(Fd(3));
        let (file_type, file_size) = self
            .inode_table
            .get(&inode)
            .map(|InodeImpl { file_stat, .. }| {
                (file_stat.file_type.clone(), file_stat.file_size.clone())
            })
            .ok_or(ErrNo::BadF)?;
        let fd_stat = FdStat {
            file_type,
            flags,
            rights_base,
            rights_inheriting,
        };
        self.file_table.insert(
            next_fd,
            FileTableEntry {
                inode,
                fd_stat,
                offset: 0,
                advice: vec![(0, file_size, Advice::Normal)],
            },
        );
        Ok(next_fd)
    }

    pub(crate) fn path_remove_directory(&mut self, _fd: &Fd, _path: String) -> ErrNo {
        unimplemented!()
    }

    pub(crate) fn path_rename(
        &mut self,
        _old_fd: &Fd,
        _old_path: String,
        _new_fd: &Fd,
        _new_path: String,
    ) -> ErrNo {
        unimplemented!()
    }
}
