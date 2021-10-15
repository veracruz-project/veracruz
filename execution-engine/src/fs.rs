//! A synthetic filesystem.
//!
//! This virtual file system(VFS) for Veracruz runtime and axecution engine.
//! The VFS adopts most WASI API with *strict typing* and *Rust-style error handling*.
//! The Veracruz runtime will use this VFS directly, while any execution engine
//! can wrap all methods here to match the WASI API.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::{
    collections::HashMap,
    convert::AsRef,
    path::{Path, PathBuf},
    vec::Vec,
};
use veracruz_utils::policy::principal::{Principal, RightsTable, StandardStream};
use wasi_types::{
    Advice, DirCookie, DirEnt, ErrNo, Event, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat,
    FileType, Inode, LookupFlags, OpenFlags, PreopenType, Prestat, RiFlags, Rights, RoFlags,
    SdFlags, SetTimeFlags, SiFlags, Size, Subscription, Timestamp, Whence,
};

////////////////////////////////////////////////////////////////////////////////
// Filesystem errors.
////////////////////////////////////////////////////////////////////////////////

/// Filesystem errors either return a result of type `T` or a defined error
/// code.  The return code `ErrNo::Success` is implicit if `Ok(result)` is ever
/// returned from a filesystem function.  The result `Err(ErrNo::Success)`
/// should never be returned.
pub type FileSystemResult<T> = Result<T, ErrNo>;

////////////////////////////////////////////////////////////////////////////////
// INodes.
////////////////////////////////////////////////////////////////////////////////

/// INodes wrap the actual raw file data, and associate meta-data with that raw
/// data buffer.
#[derive(Clone, Debug)]
struct InodeEntry {
    /// The status of this file.
    file_stat: FileStat,
    /// The content of the file in bytes.  NOTE: the buffer.size() *must* match
    /// with `file_stat.file_size`.
    raw_file_data: Vec<u8>,
}

////////////////////////////////////////////////////////////////////////////////
// File-table entries.
////////////////////////////////////////////////////////////////////////////////

/// Each file table entry contains an index into the inode table, pointing to an
/// `InodeEntry`, where the static file data is stored.
#[derive(Clone, Debug)]
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

////////////////////////////////////////////////////////////////////////////////
// Filesystems.
////////////////////////////////////////////////////////////////////////////////

/// The filesystem proper, which collects together various tables and bits of
/// meta-data.
#[derive(Clone)]
pub struct FileSystem {
    /// A table of file descriptor table entries.  This is indexed by file
    /// descriptors.  
    fd_table: HashMap<Fd, FileTableEntry>,
    /// In order to quickly allocate file descriptors, we keep track of a monotonically increasing
    /// candidate, starting just above the reserved values. With this approach, file descriptors
    /// can not be re-allocated after being freed, imposing an artificial limit of 2^31 file
    /// descriptor allocations over the course of a program's execution.
    next_fd_candidate: Fd,
    /// The structure of the file system.
    ///
    /// NOTE: This is a flat map from files to inodes for now, assuming everything is in $ROOT.
    /// It will evolve to a full directory (tree) structure.
    path_table: HashMap<PathBuf, Inode>,
    /// The inode table, which points to the actual data associated with a file
    /// and other metadata.  This table is indexed by the Inode.
    inode_table: HashMap<Inode, InodeEntry>,
    /// We allocate inodes in the same way as we allocate file descriptors. Inode's are 64 bits
    /// rather than 31 bits, so the artificial limit on inode allocations is 2^64.
    next_inode_candidate: Inode,
    /// The Right table for Principal, including participants and programs.
    /// It will be used in, e.g.  `path_open` function,
    /// to constrain the `Right` of file descriptors.
    rights_table: RightsTable,
    /// Preopen FD table. Mapping the FD to dir name.
    prestat_table: HashMap<Fd, PathBuf>,
}

impl FileSystem {
    ////////////////////////////////////////////////////////////////////////////
    // Creating filesystems.
    ////////////////////////////////////////////////////////////////////////////
    /// The root directory name. It will be pre-opened for any wasm program.
    pub const ROOT_DIRECTORY: &'static str = "/";
    /// The root directory inode. It will be pre-opened for any wasm program.
    /// File descriptors 0 to 2 are reserved for the standard streams.
    pub const ROOT_DIRECTORY_INODE: Inode = Inode(3);
    /// The root directory file descriptor. It will be pre-opened for any wasm program.
    pub const ROOT_DIRECTORY_FD: Fd = Fd(3);
    /// The default initial rights on a newly created file.
    pub const DEFAULT_RIGHTS: Rights = Rights::all();

    /// Creates a new, empty filesystem.
    ///
    /// NOTE: the file descriptors 0, 1, and 2 are pre-allocated for stdin and
    /// similar.  Rust programs are going to expect that this is true, so we
    /// need to preallocate some files corresponding to those, here.
    #[inline]
    pub fn new(rights_table: RightsTable, std_streams_table: &Vec<StandardStream>) -> Self {
        let mut rst = Self {
            fd_table: HashMap::new(),
            next_fd_candidate: Fd(u32::from(Self::ROOT_DIRECTORY_FD) + 1),
            path_table: HashMap::new(),
            inode_table: HashMap::new(),
            next_inode_candidate: Inode(u64::from(Self::ROOT_DIRECTORY_INODE) + 1),
            rights_table,
            prestat_table: HashMap::new(),
        };
        // If 'dir_paths' passed to 'install_prestat' changes to be non-empty,
        // 'next_fd_candidate' and 'next_inode_candidate' will need to be increased accordingly.
        rst.install_prestat::<&Path>(&Vec::new(), std_streams_table);
        rst
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal auxiliary methods
    ////////////////////////////////////////////////////////////////////////

    /// Install standard streams (`stdin`, `stdout`, `stderr`).
    fn install_standard_streams(&mut self, std_streams_table: &Vec<StandardStream>) {
        for std_stream in std_streams_table {
            // Map each standard stream to an fd and inode.
            // Rights are assumed to be already configured by the execution engine in the rights table
            // at that point.
            // Base rights are ignored and replaced with the default rights
            let (path, fd_number, inode_number) = match std_stream {
                StandardStream::Stdin(file_rights) => (file_rights.file_name(), 0, 0),
                StandardStream::Stdout(file_rights) => (file_rights.file_name(), 1, 1),
                StandardStream::Stderr(file_rights) => (file_rights.file_name(), 2, 2),
            };
            self.install_file(&path, Inode(inode_number), "".as_bytes());
            self.install_fd(
                Fd(fd_number),
                Inode(inode_number),
                &Self::DEFAULT_RIGHTS,
                &Self::DEFAULT_RIGHTS,
            );
        }
    }

    /// Install `stdin`, `stdout`, `stderr`, `$ROOT`, and all dir in `dir_paths`,
    /// and then pre-open them.
    fn install_prestat<T: AsRef<Path> + Sized>(
        &mut self,
        dir_paths: &[T],
        std_streams_table: &Vec<StandardStream>,
    ) {
        // Pre open the standard streams.
        self.install_standard_streams(std_streams_table);

        // Install ROOT_DIRECTORY_FD is the first FD prestat will open.
        self.install_dir(Path::new(Self::ROOT_DIRECTORY), Self::ROOT_DIRECTORY_INODE);
        self.install_fd(
            Self::ROOT_DIRECTORY_FD,
            Self::ROOT_DIRECTORY_INODE,
            &Self::DEFAULT_RIGHTS,
            &Self::DEFAULT_RIGHTS,
        );
        self.prestat_table
            .insert(Self::ROOT_DIRECTORY_FD, PathBuf::from(Self::ROOT_DIRECTORY));

        // Assume the ROOT_DIRECTORY_FD is the first FD prestat will open.
        let root_fd_number = Self::ROOT_DIRECTORY_FD.0;
        let root_inode_number = Self::ROOT_DIRECTORY_INODE.0;
        for (index, path) in dir_paths.iter().enumerate() {
            let new_inode = Inode(index as u64 + root_inode_number + 1);
            let new_fd = Fd(index as u32 + root_fd_number + 1);
            self.install_dir(path, new_inode);
            self.install_fd(
                new_fd,
                new_inode,
                &Self::DEFAULT_RIGHTS,
                &Self::DEFAULT_RIGHTS,
            );
            self.prestat_table
                .insert(new_fd, path.as_ref().to_path_buf());
        }
    }

    /// Install a dir and attatch it to `inode`.
    /// NOTE: Since we do not have dir structure, it installs a file without any content for now.
    fn install_dir<T: AsRef<Path>>(&mut self, path: T, inode: Inode) {
        let file_stat = FileStat {
            device: (0u64).into(),
            inode: inode.clone(),
            file_type: FileType::Directory,
            num_links: 0,
            file_size: 0u64,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let node = InodeEntry {
            file_stat,
            raw_file_data: Vec::new(),
        };
        self.inode_table.insert(inode.clone(), node);
        self.path_table
            .insert(path.as_ref().to_path_buf(), inode.clone());
    }

    /// Install a file with content `raw_file_data` and attatch it to `inode`.
    fn install_file<T: AsRef<Path>>(&mut self, path: T, inode: Inode, raw_file_data: &[u8]) {
        let file_size = raw_file_data.len();
        let file_stat = FileStat {
            device: 0u64.into(),
            inode: inode.clone(),
            file_type: FileType::RegularFile,
            num_links: 0,
            file_size: file_size as u64,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let node = InodeEntry {
            file_stat,
            raw_file_data: raw_file_data.to_vec(),
        };
        self.inode_table.insert(inode.clone(), node);
        self.path_table
            .insert(path.as_ref().to_path_buf(), inode.clone());
    }

    /// Install a `fd` to the file system. The fd will be of type RegularFile.
    fn install_fd(
        &mut self,
        fd: Fd,
        inode: Inode,
        rights_base: &Rights,
        rights_inheriting: &Rights,
    ) {
        let fd_stat = FdStat {
            file_type: FileType::RegularFile,
            flags: FdFlags::empty(),
            rights_base: rights_base.clone(),
            rights_inheriting: rights_inheriting.clone(),
        };

        let fd_entry = FileTableEntry {
            inode: inode.clone(),
            fd_stat,
            offset: 0,
            /// Advice on how regions of the file are to be used.
            advice: Vec::new(),
        };
        self.fd_table.insert(fd.clone(), fd_entry);
    }

    /// Pick a new fd randomly.
    fn new_fd(&mut self) -> FileSystemResult<Fd> {
        let mut cur = self.next_fd_candidate;
        loop {
            if u32::from(cur) & 1 << 31 != 0 {
                return Err(ErrNo::NFile); // Not quite accurate, but this may be the best fit
            }
            let next = Fd(u32::from(cur) + 1);
            if !self.fd_table.contains_key(&cur) {
                self.next_fd_candidate = next;
                return Ok(cur);
            }
            cur = next;
        }
    }

    /// Pick a new inode randomly.
    fn new_inode(&mut self) -> FileSystemResult<Inode> {
        let mut cur = self.next_inode_candidate;
        loop {
            let next = match u64::from(cur).checked_add(1) {
                Some(next) => Inode(next),
                None => return Err(ErrNo::NFile), // Not quite accurate, but this may be the best fit
            };
            if !self.inode_table.contains_key(&cur) {
                self.next_inode_candidate = next;
                return Ok(cur);
            }
            cur = next;
        }
    }

    /// Check if `rights` is allowed in `fd`
    fn check_right(&self, fd: &Fd, rights: Rights) -> FileSystemResult<()> {
        if self
            .fd_table
            .get(fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_base
            .contains(rights)
        {
            Ok(())
        } else {
            Err(ErrNo::Access)
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Operations on the filesystem. Rust style implementation of WASI API
    ////////////////////////////////////////////////////////////////////////////

    /// Allows the programmer to declare how they intend to use various parts of
    /// a file to the runtime.
    #[inline]
    pub(crate) fn fd_advise(
        &mut self,
        fd: Fd,
        offset: FileSize,
        len: FileSize,
        adv: Advice,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_ADVISE)?;
        let entry = self.fd_table.get_mut(&fd).ok_or(ErrNo::BadF)?;
        entry.advice.push((offset, len, adv));
        Ok(())
    }

    /// The stub implementation of `fd_allocate`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn fd_allocate(
        &mut self,
        _fd: Fd,
        _offset: FileSize,
        _len: FileSize,
    ) -> FileSystemResult<()> {
        Err(ErrNo::NoSys)
    }

    /// Implements the `fd_close` operation on the filesystem, which closes a
    /// file descriptor.  Returns `ErrNo::BadF`, if `fd` is not a current file-descriptor.
    #[inline]
    pub(crate) fn fd_close(&mut self, fd: Fd) -> FileSystemResult<()> {
        self.fd_table.remove(&fd).ok_or(ErrNo::BadF)?;
        Ok(())
    }

    /// The stub implementation of `fd_datasync`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn fd_datasync(&mut self, fd: Fd) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_DATASYNC)?;
        Err(ErrNo::NoSys)
    }

    /// Return a copy of the status of the file descriptor, `fd`.
    #[inline]
    pub(crate) fn fd_fdstat_get(&self, fd: Fd) -> FileSystemResult<FdStat> {
        Ok(self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.fd_stat.clone())
    }

    /// Change the flag associated with the file descriptor, `fd`.
    #[inline]
    pub(crate) fn fd_fdstat_set_flags(&mut self, fd: Fd, flags: FdFlags) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_FDSTAT_SET_FLAGS)?;
        self.fd_table.get_mut(&fd).ok_or(ErrNo::BadF)?.fd_stat.flags = flags;
        Ok(())
    }

    /// Change the right associated with the file descriptor, `fd`.
    #[inline]
    pub(crate) fn fd_fdstat_set_rights(
        &mut self,
        fd: Fd,
        rights_base: Rights,
        rights_inheriting: Rights,
    ) -> FileSystemResult<()> {
        let mut fd_stat = self.fd_table.get_mut(&fd).ok_or(ErrNo::BadF)?.fd_stat;
        fd_stat.rights_base = rights_base;
        fd_stat.rights_inheriting = rights_inheriting;
        Ok(())
    }

    /// Return a copy of the status of the open file pointed by the file descriptor, `fd`.
    pub(crate) fn fd_filestat_get(&self, fd: Fd) -> FileSystemResult<FileStat> {
        let inode = self
            .fd_table
            .get(&fd)
            .map(|fte| fte.inode)
            .ok_or(ErrNo::BadF)?;

        Ok(self
            .inode_table
            .get(&inode)
            .ok_or(ErrNo::NoEnt)?
            .file_stat
            .clone())
    }

    /// Change the size of the open file pointed by the file descriptor, `fd`. The extra bytes are
    /// filled with ZERO.
    pub(crate) fn fd_filestat_set_size(&mut self, fd: Fd, size: FileSize) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_FILESTAT_SET_SIZE)?;
        let inode = self
            .fd_table
            .get(&fd)
            .map(|FileTableEntry { inode, .. }| inode.clone())
            .ok_or(ErrNo::BadF)?;

        let inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::NoEnt)?;
        inode_impl.file_stat.file_size = size;
        inode_impl.raw_file_data.resize(size as usize, 0);
        Ok(())
    }

    /// Change the time of the open file pointed by the file descriptor, `fd`. If `fst_flags`
    /// contains `ATIME_NOW` or `MTIME_NOW`, the method immediately returns unsupported error
    /// `NoSys`.
    pub(crate) fn fd_filestat_set_times(
        &mut self,
        fd: Fd,
        atime: Timestamp,
        mtime: Timestamp,
        fst_flags: SetTimeFlags,
        current_time: Timestamp,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_FILESTAT_SET_TIMES)?;
        let inode = self
            .fd_table
            .get(&fd)
            .map(|FileTableEntry { inode, .. }| inode.clone())
            .ok_or(ErrNo::BadF)?;
        let mut inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::NoEnt)?;
        if fst_flags.contains(SetTimeFlags::ATIME_NOW) {
            inode_impl.file_stat.atime = current_time;
        } else if fst_flags.contains(SetTimeFlags::MTIME_NOW) {
            inode_impl.file_stat.mtime = current_time;
        } else if fst_flags.contains(SetTimeFlags::ATIME) {
            inode_impl.file_stat.atime = atime;
        } else if fst_flags.contains(SetTimeFlags::MTIME) {
            inode_impl.file_stat.mtime = mtime;
        }
        Ok(())
    }

    /// A rust-style implementation for `fd_pread`.
    /// The actual WASI spec, requires, after `fd`, an extra parameter of type IoVec,
    /// to which the content should be written.
    /// Also the WASI requires the function returns the number of byte read.
    /// However, the implementation of WASI spec of fd_pread depends on
    /// how a particular execution engine handles the memory.
    /// That is, different engines provide different API to interact the linear memory
    /// space of WASM. Hence, the method here return the read bytes as `Vec<u8>`.
    pub(crate) fn fd_pread(
        &mut self,
        fd: Fd,
        buffer_len: usize,
        offset: FileSize,
    ) -> FileSystemResult<Vec<u8>> {
        self.check_right(&fd, Rights::FD_READ)?;
        let inode = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.inode;
        // NOTE: It should be safe to convert a u64 to usize.
        let offset = offset as usize;

        let buffer = &self
            .inode_table
            .get(&inode)
            .ok_or(ErrNo::NoEnt)?
            .raw_file_data;
        //          offset
        //             v
        // ---------------------------------------------
        // |  ....     | to_read              |        |
        // ---------------------------------------------
        //             v ...  read_length ... v
        //             ------------------------
        //             | rst                  |
        //             ------------------------
        let (_, to_read) = buffer.split_at(offset);
        let read_length = if buffer_len < to_read.len() {
            buffer_len
        } else {
            to_read.len()
        };
        let (rst, _) = to_read.split_at(read_length);
        Ok(rst.to_vec())
    }

    /// Return the status of a pre-opened Fd `fd`.
    #[inline]
    pub(crate) fn fd_prestat_get(&mut self, fd: Fd) -> FileSystemResult<Prestat> {
        let path = self.prestat_table.get(&fd).ok_or(ErrNo::BadF)?;
        let resource_type = PreopenType::Dir {
            name_len: path.as_os_str().len() as u32,
        };
        Ok(Prestat { resource_type })
    }

    /// Return the path of a pre-opened Fd `fd`. The path must be consistent with the status returned by `fd_prestat_get`
    #[inline]
    pub(crate) fn fd_prestat_dir_name(&mut self, fd: Fd) -> FileSystemResult<PathBuf> {
        let path = self.prestat_table.get(&fd).ok_or(ErrNo::BadF)?;
        Ok(path.to_path_buf())
    }

    /// A rust-style implementation for `fd_pwrite`.
    /// The actual WASI spec, requires that `ciovec` is of type Vec<IoVec>.
    /// However, the implementation of WASI spec of fd_pread depends on
    /// how a particular execution engine handles the memory.
    /// That is, different engines provide different API to interact the linear memory
    /// space of WASM.
    pub(crate) fn fd_pwrite(
        &mut self,
        fd: Fd,
        buf: &[u8],
        offset: FileSize,
    ) -> FileSystemResult<Size> {
        self.check_right(&fd, Rights::FD_WRITE)?;
        let inode = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.inode;

        let inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::NoEnt)?;
        //          offset
        //             v  .. remain_length .. v
        // ----------------------------------------------
        // |  ....     | to_write             0 0 ...   |
        // ----------------------------------------------
        //             v     ...    buf.len()    ...    v
        //             ----------------------------------
        //             | buf                            |
        //             ----------------------------------
        let remain_length = (inode_impl.file_stat.file_size - offset) as usize;
        let offset = offset as usize;
        if remain_length <= buf.len() {
            let mut grow_vec = vec![0; buf.len() - remain_length];
            inode_impl.raw_file_data.append(&mut grow_vec);
        }
        let rst = buf.len();
        inode_impl.raw_file_data[offset..(offset + rst)].copy_from_slice(&buf);
        inode_impl.file_stat.file_size = inode_impl.raw_file_data.len() as u64;
        Ok(rst as Size)
    }

    /// A rust-style base implementation for `fd_read`. It directly calls `fd_pread` with the
    /// current `offset` of Fd `fd` and then calls `fd_seek`.
    pub(crate) fn fd_read(&mut self, fd: Fd, len: usize) -> FileSystemResult<Vec<u8>> {
        self.check_right(&fd, Rights::FD_READ)?;
        let offset = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset;

        let rst = self.fd_pread(fd, len, offset)?;
        self.fd_seek(fd, rst.len() as i64, Whence::Current)?;
        Ok(rst)
    }

    /// The stub implementation of `fd_readdir`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn fd_readdir(
        &mut self,
        fd: Fd,
        _cookie: DirCookie,
    ) -> FileSystemResult<Vec<DirEnt>> {
        self.check_right(&fd, Rights::FD_READDIR)?;
        Err(ErrNo::NoSys)
    }

    /// Atomically renumbers the `old_fd` to the `new_fd`.  Note that as
    /// execution engine is single-threaded this is atomic from the WASM program's
    /// point of view.
    pub(crate) fn fd_renumber(&mut self, old_fd: Fd, new_fd: Fd) -> FileSystemResult<()> {
        let entry = self.fd_table.get(&old_fd).ok_or(ErrNo::BadF)?.clone();
        if self.fd_table.get(&new_fd).is_none() {
            self.fd_table.insert(new_fd, entry);
            self.fd_table.remove(&old_fd);
            Ok(())
        } else {
            Err(ErrNo::BadF)
        }
    }

    /// Change the offset of Fd `fd`.
    pub(crate) fn fd_seek(
        &mut self,
        fd: Fd,
        delta: FileDelta,
        whence: Whence,
    ) -> FileSystemResult<FileSize> {
        self.check_right(&fd, Rights::FD_SEEK)?;
        let FileTableEntry { inode, offset, .. } = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?;
        let file_size = self
            .inode_table
            .get(inode)
            .ok_or(ErrNo::NoEnt)?
            .file_stat
            .file_size;

        let new_base_offset = match whence {
            Whence::Current => *offset,
            Whence::End => file_size,
            Whence::Start => 0,
        };

        // NOTE: Ensure the computation does not overflow.
        let new_offset: FileSize = if delta >= 0 {
            // It is safe to convert a positive i64 to u64.
            let t_offset = new_base_offset + (delta.abs() as u64);
            // If offset is greater the file size, then expand the file.
            if t_offset > file_size {
                self.fd_filestat_set_size(fd.clone(), t_offset)?;
            }
            t_offset
        } else {
            // It is safe to convert a positive i64 to u64.
            if (delta.abs() as u64) > new_base_offset {
                return Err(ErrNo::SPipe);
            }
            new_base_offset - (delta.abs() as u64)
        };

        // Update the offset
        self.fd_table.get_mut(&fd).ok_or(ErrNo::BadF)?.offset = new_offset;
        Ok(new_offset)
    }

    /// The stub implementation of `fd_sync`. It is a no-op now.
    #[inline]
    pub(crate) fn fd_sync(&mut self, fd: Fd) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_SYNC)?;
        Ok(())
    }

    /// Returns the current offset associated with the file descriptor.
    #[inline]
    pub(crate) fn fd_tell(&self, fd: Fd) -> FileSystemResult<FileSize> {
        self.check_right(&fd, Rights::FD_TELL)?;
        Ok(self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset.clone())
    }

    /// A rust-style base implementation for `fd_write`. It directly calls `fd_pwrite` with the
    /// current `offset` of Fd `fd` and then calls `fd_seek`.
    pub(crate) fn fd_write(&mut self, fd: Fd, buf: &[u8]) -> FileSystemResult<Size> {
        self.check_right(&fd, Rights::FD_WRITE)?;
        let offset = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset;

        let rst = self.fd_pwrite(fd, buf, offset)?;
        self.fd_seek(fd, rst as i64, Whence::Current)?;
        Ok(rst)
    }

    /// The stub implementation of `path_create_directory`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_create_directory<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _path: T,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::PATH_CREATE_DIRECTORY)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        Err(ErrNo::NoSys)
    }

    /// Return a copy of the status of the file at path `path`. We only support the searching from the root Fd. We ignore searching flag `flags`.
    pub(crate) fn path_filestat_get<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _flags: LookupFlags,
        path: T,
    ) -> FileSystemResult<FileStat> {
        let path = path.as_ref();
        self.check_right(&fd, Rights::PATH_FILESTAT_GET)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        let inode = self.path_table.get(path).ok_or(ErrNo::NoEnt)?;
        Ok(self
            .inode_table
            .get(&inode)
            .ok_or(ErrNo::BadF)?
            .file_stat
            .clone())
    }

    /// Change the time of the open file at `path` If `fst_flags`
    /// contains `ATIME_NOW` or `MTIME_NOW`, the method immediately returns unsupported error
    /// `NoSys`. We only support searching from the root Fd. We ignore searching flag `flags`.
    pub(crate) fn path_filestat_set_times<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _flags: LookupFlags,
        path: T,
        atime: Timestamp,
        mtime: Timestamp,
        fst_flags: SetTimeFlags,
        current_time: Timestamp,
    ) -> FileSystemResult<()> {
        let path = path.as_ref();
        self.check_right(&fd, Rights::PATH_FILESTAT_SET_TIMES)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }

        let inode = self.path_table.get(path).ok_or(ErrNo::NoEnt)?;
        let mut inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::BadF)?;
        if fst_flags.contains(SetTimeFlags::ATIME_NOW) {
            inode_impl.file_stat.atime = current_time;
        } else if fst_flags.contains(SetTimeFlags::MTIME_NOW) {
            inode_impl.file_stat.mtime = current_time;
        } else if fst_flags.contains(SetTimeFlags::ATIME) {
            inode_impl.file_stat.atime = atime;
        } else if fst_flags.contains(SetTimeFlags::MTIME) {
            inode_impl.file_stat.mtime = mtime;
        }
        Ok(())
    }

    /// A minimum functionality of opening a file or directory on behalf of the principal `principal`.
    /// We only support search from the root Fd. We ignore the dir look up flag.
    ///
    /// The behaviour of `path_open` varies based on the open flags `oflags`:
    /// * if no flag is set, open a file at the path, if exists, starting from the directory opened by the file descriptor `fd`;
    /// * if `EXCL` is set, `path_open` fails if the path exists;
    /// * if `CREATE` is set, create a new file at the path if the path does not exist;
    /// * if `TRUNC` is set, the file at the path is truncated, that is, clean the content and set the file size to ZERO; and
    /// * if `DIRECTORY` is set, `path_open` fails if the path is not a directory. **NOT SUUPORT**.
    pub(crate) fn path_open<T: AsRef<Path>>(
        &mut self,
        principal: &Principal,
        // The parent fd for searching
        fd: Fd,
        _dirflags: LookupFlags,
        path: T,
        oflags: OpenFlags,
        rights_base: Rights,
        rights_inheriting: Rights,
        flags: FdFlags,
    ) -> FileSystemResult<Fd> {
        let path = path.as_ref();
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        // NOTE: A pontential better way to control capability is to
        // separate the Fd space of of different participants.

        // Read the right related to the principal.
        let principal_right = if *principal != Principal::InternalSuperUser {
            self.get_right(&principal, path)?
        } else {
            Rights::all()
        };
        // Intersect with the inheriting right from `fd`
        let fd_inheriting = self
            .fd_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_inheriting;
        let principal_right = principal_right & fd_inheriting;
        // Check the right of the program on path_open
        if !principal_right.contains(Rights::PATH_OPEN) {
            return Err(ErrNo::Access);
        }
        let rights_base = rights_base & principal_right;
        let rights_inheriting = rights_inheriting & principal_right;
        // Several oflags logic, inc. `create`, `excl` and `trunc`. We ignore `directory`.
        let inode = match self.path_table.get(path) {
            Some(i) => {
                // If file exists and `excl` is set, return `Exist` error.
                if oflags.contains(OpenFlags::EXCL) {
                    return Err(ErrNo::Exist);
                }
                i.clone()
            }
            None => {
                // If file does NOT exists and `create` is NOT set, return `NoEnt` error.
                if !oflags.contains(OpenFlags::CREATE) {
                    return Err(ErrNo::NoEnt);
                }
                // Check the right of the program on create file
                if !principal_right.contains(Rights::PATH_CREATE_FILE) {
                    return Err(ErrNo::Access);
                }
                let new_inode = self.new_inode()?;
                self.install_file(path, new_inode, &vec![]);
                new_inode
            }
        };
        // Truncate the file if `trunc` flag is set.
        if oflags.contains(OpenFlags::TRUNC) {
            // Check the right of the program on truacate
            if !principal_right.contains(Rights::PATH_FILESTAT_SET_SIZE) {
                return Err(ErrNo::Access);
            }
            let inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::NoEnt)?;
            inode_impl.raw_file_data = Vec::new();
            inode_impl.file_stat.file_size = 0u64;
        }
        let new_fd = self.new_fd()?;
        let FileStat {
            file_type,
            file_size,
            ..
        } = self.inode_table.get(&inode).ok_or(ErrNo::BadF)?.file_stat;
        let fd_stat = FdStat {
            file_type,
            flags,
            rights_base,
            rights_inheriting,
        };
        self.fd_table.insert(
            new_fd,
            FileTableEntry {
                inode,
                fd_stat,
                offset: 0,
                advice: vec![(0, file_size, Advice::Normal)],
            },
        );
        Ok(new_fd)
    }

    /// The stub implementation of `path_readlink`. Return unsupported error `NoSys`.
    /// We only support the searching from the root Fd.
    #[inline]
    pub(crate) fn path_readlink<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _path: T,
    ) -> FileSystemResult<Vec<u8>> {
        self.check_right(&fd, Rights::PATH_READLINK)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_remove_directory`. Return unsupported error `NoSys`.
    /// We only support the searching from the root Fd.
    #[inline]
    pub(crate) fn path_remove_directory<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _path: T,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::PATH_REMOVE_DIRECTORY)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_rename`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_rename<T: AsRef<Path>, R: AsRef<Path>>(
        &mut self,
        old_fd: Fd,
        _old_path: T,
        new_fd: Fd,
        _new_path: R,
    ) -> FileSystemResult<()> {
        self.check_right(&old_fd, Rights::PATH_RENAME_SOURCE)?;
        self.check_right(&new_fd, Rights::PATH_RENAME_TARGET)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_rename`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_link<T: AsRef<Path>, R: AsRef<Path>>(
        &mut self,
        old_fd: Fd,
        _old_flag: LookupFlags,
        _old_path: T,
        new_fd: Fd,
        _new_path: R,
    ) -> FileSystemResult<()> {
        self.check_right(&old_fd, Rights::PATH_LINK_SOURCE)?;
        self.check_right(&new_fd, Rights::PATH_LINK_TARGET)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_symlink`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_symlink<T: AsRef<Path>, R: AsRef<Path>>(
        &mut self,
        _old_path: T,
        fd: Fd,
        _new_path: R,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::PATH_SYMLINK)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_unlink_file`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_unlink_file<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _path: T,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::PATH_UNLINK_FILE)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `poll_oneoff`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn poll_oneoff(
        &mut self,
        _subscriptions: Vec<Subscription>,
        _events: Vec<Event>,
    ) -> FileSystemResult<Size> {
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_recv`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_recv(
        &mut self,
        socket: Fd,
        _buffer_len: usize,
        _ri_flags: RiFlags,
    ) -> FileSystemResult<(Vec<u8>, RoFlags)> {
        self.check_right(&socket, Rights::FD_READ)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_send`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_send(
        &mut self,
        socket: Fd,
        _buf: &[u8],
        _si_flags: SiFlags,
    ) -> FileSystemResult<Size> {
        self.check_right(&socket, Rights::FD_WRITE)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_shutdown`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_shutdown(&mut self, socket: Fd, _flags: SdFlags) -> FileSystemResult<()> {
        self.check_right(&socket, Rights::SOCK_SHUTDOWN)?;
        Err(ErrNo::NoSys)
    }

    ////////////////////////////////////////////////////////////////////////
    // Public interface for the filesystem.
    // It will be used by the veracruz runtime.
    ////////////////////////////////////////////////////////////////////////

    /// Write to a file on path `file_name`. If `is_append` is set, `data` will be append to `file_name`.
    /// Otherwise this file will be truncated. The `principal` must have the right on `path_open`,
    /// `fd_write` and `fd_seek`.
    pub fn write_file_by_filename<T: AsRef<Path>>(
        &mut self,
        principal: &Principal,
        file_name: T,
        data: &[u8],
        is_append: bool,
    ) -> Result<(), ErrNo> {
        let file_name = file_name.as_ref();
        let oflag = OpenFlags::CREATE
            | if !is_append {
                OpenFlags::TRUNC
            } else {
                OpenFlags::empty()
            };
        let fd = self.path_open(
            principal,
            FileSystem::ROOT_DIRECTORY_FD,
            LookupFlags::empty(),
            file_name,
            oflag,
            FileSystem::DEFAULT_RIGHTS,
            FileSystem::DEFAULT_RIGHTS,
            FdFlags::empty(),
        )?;
        if !self
            .fd_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_base
            .contains(Rights::FD_WRITE | Rights::FD_SEEK)
        {
            return Err(ErrNo::Access);
        }
        if is_append {
            self.fd_seek(fd, 0, Whence::End)?;
        }
        self.fd_write(fd, data)?;
        self.fd_close(fd)?;
        Ok(())
    }

    /// Read from a file on path `file_name`.
    /// The `principal` must have the right on `path_open`,
    /// `fd_read` and `fd_seek`.
    pub fn read_file_by_filename<T: AsRef<Path>>(
        &mut self,
        principal: &Principal,
        file_name: T,
    ) -> Result<Vec<u8>, ErrNo> {
        let file_name = file_name.as_ref();
        let fd = self.path_open(
            principal,
            FileSystem::ROOT_DIRECTORY_FD,
            LookupFlags::empty(),
            file_name,
            OpenFlags::empty(),
            FileSystem::DEFAULT_RIGHTS,
            FileSystem::DEFAULT_RIGHTS,
            FdFlags::empty(),
        )?;
        if !self
            .fd_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_base
            .contains(Rights::FD_READ | Rights::FD_SEEK)
        {
            return Err(ErrNo::Access);
        }
        let file_stat = self.fd_filestat_get(fd)?;
        let rst = self.fd_read(fd, file_stat.file_size as usize)?;
        self.fd_close(fd)?;
        Ok(rst)
    }

    /// Get the maximum right associated to the principal on the file
    fn get_right<T: AsRef<Path>>(
        &self,
        principal: &Principal,
        file_name: T,
    ) -> FileSystemResult<Rights> {
        let file_name = file_name.as_ref();
        self.rights_table
            .get(principal)
            .ok_or(ErrNo::Access)?
            .get(file_name)
            .map(|r| r.clone())
            .ok_or(ErrNo::Access)
    }
}
