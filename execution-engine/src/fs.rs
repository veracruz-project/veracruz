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
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::{collections::HashMap, convert::{TryInto, AsRef}, string::ToString, string::String, vec::Vec};
use wasi_types::{
    Advice, DirCookie, DirEnt, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, Inode,
    LookupFlags, OpenFlags, Prestat, Rights, Size, Whence, Timestamp, FileType,
    PreopenType, SetTimeFlags, ClockId, Event, Subscription, SdFlags, SiFlags, RiFlags, RoFlags
};
use veracruz_utils::policy::principal::{RightTable, Principal};
use platform_services::{getrandom, result};
use log::info;

////////////////////////////////////////////////////////////////////////////////
// Filesystem errors.
////////////////////////////////////////////////////////////////////////////////

/// Filesystem errors either return a result of type `T` or a defined error
/// code.  The return code `ErrNo::Success` is implicit if `Ok(result)` is ever
/// returned from a filesystem function.  The result `Err(ErrNo::Success)`
/// should never be returned.
pub type FileSystemError<T> = Result<T, ErrNo>;

////////////////////////////////////////////////////////////////////////////////
// INodes.
////////////////////////////////////////////////////////////////////////////////

/// INodes wrap the actual raw file data, and associate meta-data with that raw
/// data buffer.
#[derive(Clone, Debug)]
struct InodeImpl {
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
/// `InodeImpl`, where the static file data is stored.
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
    file_table: HashMap<Fd, FileTableEntry>,
    /// The structure of the file system.
    ///
    /// NOTE: This is a flat map from files to inodes for now.  It will evolve
    /// to a full directory (tree) structure.
    path_table: HashMap<String, Inode>,
    /// The inode table, which points to the actual data associated with a file
    /// and other metadata.  This table is indexed by the Inode.
    inode_table: HashMap<Inode, InodeImpl>,
    /// The Right table for Principal, including participants and programs. 
    /// It will be used in, e.g.  `path_open` function, 
    /// to constrain the `Right` of file descriptors.
    right_table: RightTable,
    /// Preopen FD table. Mapping the FD to dir name.
    prestat_table: HashMap<Fd, String>,
}

impl FileSystem {
    ////////////////////////////////////////////////////////////////////////////
    // Creating filesystems.
    ////////////////////////////////////////////////////////////////////////////
    /// The root directory name. It will be pre-opened for any wasm program.
    pub const ROOT_DIRECTORY: &'static str = "/";
    /// The root directory inode. It will be pre-opened for any wasm program.
    pub const ROOT_DIRECTORY_INODE: Inode = Inode(2);
    /// The root directory file descriptor. It will be pre-opened for any wasm program.
    pub const ROOT_DIRECTORY_FD: Fd = Fd(3);
    /// The default initial rights on a newly created file.
    pub const DEFAULT_RIGHTS: Rights = Rights::from_bits_truncate(Rights::FD_DATASYNC.bits() | Rights::FD_READ.bits() | Rights::FD_SEEK.bits() | Rights::FD_FDSTAT_SET_FLAGS.bits() | Rights::FD_SYNC.bits() | Rights::FD_TELL.bits() | Rights::FD_WRITE.bits() | Rights::FD_ADVISE.bits() | Rights::FD_ALLOCATE.bits() | Rights::PATH_CREATE_DIRECTORY.bits() | Rights::PATH_CREATE_FILE.bits() | Rights::PATH_LINK_SOURCE.bits() | Rights::PATH_LINK_TARGET.bits() | Rights::PATH_OPEN.bits() | Rights::PATH_READLINK.bits() | Rights::PATH_RENAME_SOURCE.bits() | Rights::PATH_RENAME_TARGET.bits() | Rights::PATH_FILESTAT_GET.bits() | Rights::PATH_FILESTAT_SET_SIZE.bits() | Rights::FD_FILESTAT_SET_TIMES.bits() | Rights::PATH_SYMLINK.bits() | Rights::PATH_REMOVE_DIRECTORY.bits() | Rights::PATH_UNLINK_FILE.bits() | Rights::POLL_FD_READWRITE.bits() | Rights::SOCK_SHUTDOWN.bits());

    /// Creates a new, empty filesystem.
    ///
    /// NOTE: the file descriptors 0, 1, and 2 are pre-allocated for stdin and
    /// similar.  Rust programs are going to expect that this is true, so we
    /// need to preallocate some files corresponding to those, here.
    #[inline]
    pub fn new(right_table : RightTable) -> Self {
        let mut rst = Self {
            file_table: HashMap::new(),
            path_table: HashMap::new(),
            inode_table: HashMap::new(),
            right_table,
            prestat_table: HashMap::new(),
        };
        rst.install_prestat(&vec![""]);
        rst
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal auxiliary methods
    ////////////////////////////////////////////////////////////////////////

    /// Install `stdin`, `stdout`, `stderr`, `$ROOT`, and all dir in `dir_paths`,
    /// and then pre-open them. 
    fn install_prestat(&mut self, dir_paths: &[&str]) {
        // Pre open the stdin stdout and stderr.
        self.install_file("stderr",Inode(0), "".as_bytes());
        self.install_fd(Fd(0),Inode(0), &Rights::FD_READ, &Rights::FD_READ);
        self.install_file("stdin",Inode(1), "".as_bytes());
        self.install_fd(Fd(1),Inode(1), &Rights::FD_READ, &Rights::FD_READ);
        self.install_file("stderr",Inode(2), "".as_bytes());
        self.install_fd(Fd(2),Inode(2), &Rights::FD_READ, &Rights::FD_READ);

        // Install ROOT_DIRECTORY_FD is the first FD prestat will open.
        self.install_dir(Self::ROOT_DIRECTORY, Self::ROOT_DIRECTORY_INODE);
        self.install_fd(Self::ROOT_DIRECTORY_FD, Self::ROOT_DIRECTORY_INODE, &Self::DEFAULT_RIGHTS, &Self::DEFAULT_RIGHTS);
        self.prestat_table.insert(Self::ROOT_DIRECTORY_FD, Self::ROOT_DIRECTORY.to_string());

        // Assume the ROOT_DIRECTORY_FD is the first FD prestat will open.
        let root_fd_number = Self::ROOT_DIRECTORY_FD.0;
        for (index, path) in dir_paths.iter().enumerate() {
            let index = index as u32;
            let new_fd = Fd(index + root_fd_number + 1);
            self.install_dir(path,Self::ROOT_DIRECTORY_INODE);
            self.install_fd(new_fd,Self::ROOT_DIRECTORY_INODE, &Self::DEFAULT_RIGHTS, &Self::DEFAULT_RIGHTS);
            self.prestat_table.insert(new_fd, path.to_string());
        }
    }
    
    /// Install a dir and attatch it to `inode`. 
    /// NOTE: Since we do not have dir structure, it installs a file without any content for now.
    fn install_dir(&mut self, path: impl AsRef<str>, inode : Inode) {
        let file_stat = FileStat{
            device: (0u64).into(),
            inode : inode.clone(),
            file_type: FileType::Directory,
            num_links: 0,
            file_size : 0u64,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let node = InodeImpl {
            file_stat,
            raw_file_data : Vec::new(),
        };
        self.inode_table.insert(inode.clone(),node);
        self.path_table.insert(path.as_ref().to_string(),inode.clone());
    }

    /// Install a file with content `raw_file_data` and attatch it to `inode`. 
    fn install_file(&mut self, path: impl AsRef<str>, inode : Inode, raw_file_data : &[u8]) {
        let file_size = raw_file_data.len();
        let file_stat = FileStat{
            device: 0u64.into(),
            inode : inode.clone(),
            file_type: FileType::RegularFile,
            num_links: 0,
            file_size : file_size as u64,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let node = InodeImpl {
            file_stat,
            raw_file_data : raw_file_data.to_vec(),
        };
        self.inode_table.insert(inode.clone(),node);
        self.path_table.insert(path.as_ref().to_string(),inode.clone());
    }

    /// Install a `fd` to the file system. The fd will be of type RegularFile.
    fn install_fd(&mut self, fd : Fd, inode : Inode, rights_base : &Rights, rights_inheriting : &Rights) {

        let fd_stat = FdStat {
            file_type : FileType::RegularFile,
            flags : FdFlags::empty(),
            rights_base : rights_base.clone(),
            rights_inheriting : rights_inheriting.clone(),
        };

        let fd_entry = FileTableEntry {
            inode: inode.clone(),
            fd_stat,
            offset: 0,
            /// Advice on how regions of the file are to be used.
            advice: Vec::new(),
        };
        self.file_table.insert(fd.clone(),fd_entry);
    }

    /// Return a random u32
    fn random_u32(&self) -> FileSystemError<u32> {
        let result: [u8; 4] = self.random_get(4)?.as_slice().try_into().map_err(|_| ErrNo::Inval)?;
        Ok(u32::from_le_bytes(result))
    }

    /// Return a random u64
    fn random_u64(&self) -> FileSystemError<u64> {
        let result: [u8; 8] = self.random_get(8)?.as_slice().try_into().map_err(|_| ErrNo::Inval)?;
        Ok(u64::from_le_bytes(result))
    }

    /// Pick a new fd randomly.
    fn new_fd(&self) -> FileSystemError<Fd> {
        loop {
            let new_fd = self.random_u32()?.into();
            if !self.file_table.contains_key(&new_fd) {
                return Ok(new_fd);
            }
        }
    }

    /// Pick a new inode randomly.
    fn new_inode(&self) -> FileSystemError<Inode> {
        loop {
            let new_inode = Inode(self.random_u64()?);
            if !self.inode_table.contains_key(&new_inode) {
                return Ok(new_inode);
            }
        }
    }

    /// Check if `op` is allowed in `fd`
    fn check_right(&self, fd : &Fd, rights: Rights) -> FileSystemError<()> {
        if self.file_table.get(fd).ok_or(ErrNo::BadF)?.fd_stat.rights_base.contains(rights) {
            Ok(())
        } else {
            Err(ErrNo::Access)
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Operations on the filesystem. Rust style implementation of WASI API
    ////////////////////////////////////////////////////////////////////////////

    /// The stub implementation of `clock_res_get`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn clock_res_get(
        &self,
        clock_id: ClockId,
    ) -> FileSystemError<Timestamp> {
        info!("call clock_res_get on clock_id {:?}", clock_id);
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `clock_time_get`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn clock_time_get(
        &self,
        clock_id: ClockId,
        precision: Timestamp,
    ) -> FileSystemError<Timestamp> {
        info!("call clock_time_get on clock_id {:?}, precision {:?}", clock_id, precision);
        Err(ErrNo::NoSys)
    }

    /// Allows the programmer to declare how they intend to use various parts of
    /// a file to the runtime.
    pub(crate) fn fd_advise(
        &mut self,
        fd: Fd,
        offset: FileSize,
        len: FileSize,
        adv: Advice,
    ) -> FileSystemError<()> {
        info!("call fd_advise on fd {:?}, offset {:?}, len {:?}, advice {:?}", fd, offset, len, adv);
        self.check_right(&fd, Rights::FD_ADVISE)?;
        let entry = self.file_table.get_mut(&fd).ok_or(ErrNo::BadF)?; 
        entry.advice.push((offset, len, adv));
        Ok(())
    }

    /// The stub implementation of `fd_allocate`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn fd_allocate(
        &mut self,
        fd : Fd,
        offset: FileSize,
        len: FileSize,
    ) -> FileSystemError<()> {
        info!("call fd_allocate on fd {:?}, offset {:?}, len {:?}", fd, offset, len);
        Err(ErrNo::NoSys)
    }

    /// Implements the `fd_close` operation on the filesystem, which closes a
    /// file descriptor.  Returns `ErrNo::BadF`, if `fd` is not a current file-descriptor. 
    pub(crate) fn fd_close(&mut self, fd: Fd) -> FileSystemError<()> {
        info!("call fd_close on {:?}", fd);
        self.file_table.remove(&fd).ok_or(ErrNo::BadF)?;
        Ok(())
    }

    /// The stub implementation of `fd_datasync`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn fd_datasync(
        &mut self,
        fd: Fd,
    ) -> FileSystemError<()> {
        info!("call fd_datasync on fd {:?}", fd);
        self.check_right(&fd, Rights::FD_DATASYNC)?;
        Err(ErrNo::NoSys)
    }

    /// Return a copy of the status of the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_get(&self, fd: Fd) -> FileSystemError<FdStat> {
        info!("call fd_fdstat_get on {:?}", fd);
        Ok(self.file_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?.fd_stat.clone())
    }

    /// Change the flag associated with the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_set_flags(&mut self, fd: Fd, flags: FdFlags) -> FileSystemError<()> {
        info!("call fd_fdstat_set_flags on fd {:?} and flags {:?}", fd, flags);
        self.check_right(&fd, Rights::FD_FDSTAT_SET_FLAGS)?;
        self.file_table
            .get_mut(&fd)
            .map(|FileTableEntry { mut fd_stat, .. }| {
                fd_stat.flags = flags;
            })
            .ok_or(ErrNo::BadF)
    }

    /// Change the right associated with the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_set_rights(
        &mut self,
        fd: Fd,
        rights_base: Rights,
        rights_inheriting: Rights,
    ) -> FileSystemError<()> {
        info!("call fd_fdstat_set_rights on fd {:?}, right base {:?} and inheriting {:?}", fd,rights_base, rights_inheriting);
        let mut fd_stat = self.file_table
            .get_mut(&fd)
            .ok_or(ErrNo::BadF)?.fd_stat;
        fd_stat.rights_base = rights_base;
        fd_stat.rights_inheriting = rights_inheriting;
        Ok(())
    }

    /// Return a copy of the status of the open file pointed by the file descriptor, `fd`.
    pub(crate) fn fd_filestat_get(&self, fd: Fd) -> FileSystemError<FileStat> {
        info!("call fd_filestat_get on fd {:?}", fd);
        let inode = self
            .file_table
            .get(&fd)
            .map(|fte| fte.inode)
            .ok_or(ErrNo::BadF)?;

        Ok(self.inode_table
            .get(&inode)
            .ok_or(ErrNo::NoEnt)?.file_stat.clone())
    }

    /// Change the size of the open file pointed by the file descriptor, `fd`. The extra bypes are
    /// filled with ZERO.
    pub(crate) fn fd_filestat_set_size(&mut self, fd: Fd, size: FileSize) -> FileSystemError<()> {
        info!("call fd_filestat_set_size on fd {:?} and size {:?}", fd, size);
        self.check_right(&fd, Rights::FD_FILESTAT_SET_SIZE)?;
        let inode = self.file_table.get(&fd).map(|FileTableEntry { inode, .. }| inode.clone()).ok_or(ErrNo::BadF)?;

        let inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::NoEnt)?;
        inode_impl.file_stat.file_size = size;
        inode_impl.raw_file_data.resize(size as usize, 0);
        Ok(())
    }

    /// Change the time of the open file pointed by the file descriptor, `fd`. If `fst_flags`
    /// contains `ATIME_NOW` or `MTIME_NOW`, the method immediately returns unsupported error
    /// `NoSys`.
    pub(crate) fn fd_filestat_set_times(&mut self, fd: Fd, atime: Timestamp, mtime: Timestamp, fst_flags: SetTimeFlags) -> FileSystemError<()> {
        info!("call fd_filestat_set_times on fd {:?}, atime {:?}, mtime {:?} and fst_flags {:?}", fd, atime, mtime, fst_flags);
        self.check_right(&fd, Rights::FD_FILESTAT_SET_TIMES)?;
        let inode = self.file_table.get(&fd).map(|FileTableEntry { inode, .. }| inode.clone()).ok_or(ErrNo::BadF)?;

        let mut inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::NoEnt)?;
        if fst_flags.contains(SetTimeFlags::ATIME_NOW) {
            return Err(ErrNo::NoSys)
        } else if fst_flags.contains(SetTimeFlags::MTIME_NOW) {
            return Err(ErrNo::NoSys)
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
    /// space of WASM. Hence, the method here return the read bypes as `Vec<u8>`.
    pub(crate) fn fd_pread(
        &mut self,
        fd: Fd,
        buffer_len: usize,
        offset: FileSize,
    ) -> FileSystemError<Vec<u8>> {
        info!("call fd_pread on fd {:?} buffer_len {:?} and offset {:?}", fd, buffer_len, offset);
        self.check_right(&fd, Rights::FD_READ)?;
        let inode = self
            .file_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?.inode;
        // NOTE: It should be safe to convert a u64 to usize.
        let offset = offset as usize;

        let buffer = &self.inode_table
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
        let read_length = if buffer_len < to_read.len() { buffer_len } else { to_read.len() };
        let (rst, _) = to_read.split_at(read_length);
        info!("call fd_pread read {:?} bytes",rst.len());
        Ok(rst.to_vec())
    }

    /// Return the status of a pre-opened Fd `fd`.
    pub(crate) fn fd_prestat_get(&mut self, fd: Fd) -> FileSystemError<Prestat> {
        info!("call fd_prestat_get on {:?}",fd);
        let path = self.prestat_table.get(&fd).ok_or(ErrNo::BadF)?;
        let resource_type = PreopenType::Dir {
            name_len : path.len() as u32
        };
        Ok(Prestat{resource_type})
    }

    /// Return the path of a pre-opened Fd `fd`. The path must be consistent with the status returned by `fd_prestat_get`
    pub(crate) fn fd_prestat_dir_name(&mut self, fd: Fd) -> FileSystemError<String> {
        info!("call fd_prestat_dir_name on {:?}",fd);
        let path = self.prestat_table.get(&fd).ok_or(ErrNo::BadF)?;
        Ok(path.to_string())
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
        buf: Vec<u8>,
        offset: FileSize,
    ) -> FileSystemError<Size> {
        info!("call fd_pwrite on fd {:?}, offset {:?} and buf {:?}", fd, offset, buf.len());
        self.check_right(&fd, Rights::FD_WRITE)?;
        let inode = self
            .file_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?.inode;

        let inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::NoEnt)?; 
        info!("call fd_pwrite before: {:?}",inode_impl.raw_file_data.len());
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
            info!("call fd_pwrite grows length");
            let mut grow_vec = vec![0; buf.len() - remain_length];
            inode_impl.raw_file_data.append(&mut grow_vec);
        }
        let rst = buf.len();
        inode_impl.raw_file_data[offset..(offset + rst)].copy_from_slice(&buf);
        inode_impl.file_stat.file_size = inode_impl.raw_file_data.len() as u64;
        info!("call fd_pwrite result: {:?}",inode_impl.raw_file_data.len());
        Ok(rst as Size)
    }

    /// A rust-style base implementation for `fd_read`. It directly calls `fd_pread` with the
    /// current `offset` of Fd `fd` and then calls `fd_seek`.
    pub(crate) fn fd_read(&mut self, fd: Fd, len: usize) -> FileSystemError<Vec<u8>> {
        info!("call fd_read on {:?} and length {:?}", fd, len);
        self.check_right(&fd, Rights::FD_READ)?;
        let offset = self.file_table.get(&fd).ok_or(ErrNo::BadF)?.offset;
        info!("call fd_read new offset {:?}", offset);

        let rst = self.fd_pread(fd, len, offset)?;
        self.fd_seek(fd, rst.len() as i64, Whence::Current)?;
        Ok(rst)
    }

    /// The stub implementation of `fd_readdir`. Return unsupported error `NoSys`.
    pub(crate) fn fd_readdir(
        &mut self,
        fd: Fd,
        cookie: DirCookie,
    ) -> FileSystemError<Vec<DirEnt>> {
        info!("call fd_readdir on {:?} and cookie {:?}", fd, cookie);
        self.check_right(&fd, Rights::FD_READDIR)?;
        Err(ErrNo::NoSys)
    }

    /// Atomically renumbers the `old_fd` to the `new_fd`.  Note that as
    /// Chihuahua is single-threaded this is atomic from the WASM program's
    /// point of view.
    pub(crate) fn fd_renumber(&mut self, old_fd: Fd, new_fd: Fd) -> FileSystemError<()> {
        info!("call fd_renumber on {:?} to a new fd {:?}", old_fd, new_fd);
        let entry = self.file_table.get(&old_fd).ok_or(ErrNo::BadF)?.clone();
        if self.file_table.get(&new_fd).is_none() {
            self.file_table.insert(new_fd, entry);
            self.file_table.remove(&old_fd);
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
    ) -> FileSystemError<FileSize> {
        info!("call fd_seek on fd {:?}, delta {:?} and whence {:?}", fd, delta, whence);
        self.check_right(&fd, Rights::FD_SEEK)?;
        let FileTableEntry {
                inode, offset, ..
            } = self.file_table.get(&fd).ok_or(ErrNo::BadF)?; 
        let file_size = self.inode_table.get(inode).ok_or(ErrNo::NoEnt)?.file_stat.file_size; 

        let new_base_offset = match whence {
            Whence::Current => *offset,
            Whence::End => file_size,
            Whence::Start => 0,
        };

        info!("call fd_seek on new base offset {:?}", new_base_offset);
        // NOTE: Ensure the computation does not overflow.
        let new_offset: FileSize = if delta >= 0 {
            // It is safe to convert a positive i64 to u64.
            let t_offset = new_base_offset + (delta.abs() as u64);
            // Offset is allowed to equal to file size
            if t_offset > file_size {
                return Err(ErrNo::Inval);
            }
            t_offset
        } else {
            // It is safe to convert a positive i64 to u64.
            if (delta.abs() as u64) > new_base_offset {
                return Err(ErrNo::Inval);
            }
            new_base_offset - (delta.abs() as u64)
        };

        info!("call fd_seek on new offset {:?}", new_offset);
        // Update the offset
        self.file_table.get_mut(&fd).ok_or(ErrNo::BadF)?.offset = new_offset;
        Ok(new_offset)
    }

    /// The stub implementation of `fd_sync`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn fd_sync(
        &mut self,
        fd: Fd,
    ) -> FileSystemError<()> {
        info!("call fd_sync on fd {:?}", fd);
        self.check_right(&fd, Rights::FD_SYNC)?;
        Err(ErrNo::NoSys)
    }

    /// Returns the current offset associated with the file descriptor.
    pub(crate) fn fd_tell(&self, fd: Fd) -> FileSystemError<FileSize> {
        info!("call fd_tell on fd {:?}", fd);
        self.check_right(&fd, Rights::FD_TELL)?;
        Ok(self.file_table.get(&fd).ok_or(ErrNo::BadF)?.offset.clone())
    }

    /// A rust-style base implementation for `fd_write`. It directly calls `fd_pwrite` with the
    /// current `offset` of Fd `fd` and then calls `fd_seek`.
    pub(crate) fn fd_write(&mut self, fd: Fd, buf: Vec<u8>) -> FileSystemError<Size> {
        info!("call fd_write on {:?}", fd);
        self.check_right(&fd, Rights::FD_WRITE)?;
        let offset = self.file_table.get(&fd).ok_or(ErrNo::BadF)?.offset;

        let rst = self.fd_pwrite(fd, buf, offset)?;
        self.fd_seek(fd, rst as i64, Whence::Current)?;
        Ok(rst)
    }

    /// The stub implementation of `path_create_directory`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_create_directory(&mut self, fd: Fd, path: impl AsRef<str>) -> FileSystemError<()> {
        info!("call path_create_directory on fd {:?} and path {:?}", fd, path.as_ref());
        self.check_right(&fd, Rights::PATH_CREATE_DIRECTORY)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        Err(ErrNo::NoSys)
    }

    /// Return a copy of the status of the file at path `path`. We only support the searching from the root Fd. We ignore searching flag `flags`.
    pub(crate) fn path_filestat_get(
        &mut self,
        fd: Fd,
        flags: LookupFlags,
        path: impl AsRef<str>,
    ) -> FileSystemError<FileStat> {
        let path = path.as_ref();
        info!("call path_filestat_get on fd {:?} flag {:?} and path {:?}", fd, flags, path);
        self.check_right(&fd, Rights::PATH_FILESTAT_GET)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        let inode = self.path_table.get(path).ok_or(ErrNo::NoEnt)?;
        Ok(self.inode_table
            .get(&inode)
            .ok_or(ErrNo::BadF)?.file_stat.clone())
    }
    
    /// Change the time of the open file at `path` If `fst_flags`
    /// contains `ATIME_NOW` or `MTIME_NOW`, the method immediately returns unsupported error
    /// `NoSys`. We only support searching from the root Fd. We ignore searching flag `flags`. 
    pub(crate) fn path_filestat_set_times(
        &mut self,
        fd: Fd,
        flags: LookupFlags,
        path: impl AsRef<str>,
        atime: Timestamp,
        mtime: Timestamp,
        fst_flags: SetTimeFlags,
    ) -> FileSystemError<()> {
        let path = path.as_ref();
        info!("call path_filestat_get on fd {:?} flag {:?}, path {:?}, atime {:?}, mtime {:?} and fst_flags {:?}", fd, flags, path, atime, mtime, fst_flags);
        self.check_right(&fd, Rights::PATH_FILESTAT_SET_TIMES)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        let inode = self.path_table.get(path).ok_or(ErrNo::NoEnt)?;
        let mut inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::BadF)?;
        if fst_flags.contains(SetTimeFlags::ATIME_NOW) {
            return Err(ErrNo::NoSys)
        } else if fst_flags.contains(SetTimeFlags::MTIME_NOW) {
            return Err(ErrNo::NoSys)
        } else if fst_flags.contains(SetTimeFlags::ATIME) {
            inode_impl.file_stat.atime = atime;
        } else if fst_flags.contains(SetTimeFlags::MTIME) {
            inode_impl.file_stat.mtime = mtime;
        }
        Ok(())
    }

    /// A minimum functionality of opening a file or directory on behalf of the principal `principal`.
    /// We only support search from the root Fd. We ignore the dir look up flag.
    pub(crate) fn path_open(
        &mut self,
        principal : &Principal,
        // The parent fd for searching
        fd: Fd,
        dirflags: LookupFlags,
        path: &str,
        oflags: OpenFlags,
        rights_base: Rights,
        rights_inheriting: Rights,
        flags: FdFlags,
    ) -> FileSystemError<Fd> {
        info!("call path_open, on behalf of fd {:?} and principal {:?}, dirflag {:?}, path {:?} with open_flag {:?}, right_base {:?}, rights_inheriting {:?} and fd_flag {:?}",
            fd, principal, dirflags.bits(), path, oflags, rights_base, rights_inheriting, flags);
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
        let fd_inheriting = self.file_table.get(&fd).ok_or(ErrNo::BadF)?.fd_stat.rights_inheriting;
        let principal_right = principal_right & fd_inheriting;
        // Check the right of the program on path_open
        if !principal_right.contains(Rights::PATH_OPEN) {
            return Err(ErrNo::Access);
        }
        let rights_base = rights_base & principal_right;
        let rights_inheriting = rights_inheriting & principal_right;
        info!("call path_open, the actually right {:?} and inheriting right {:?}",
            rights_base, rights_inheriting);
        // Several oflags logic, inc. `create`, `excl` and `trunc`. We ignore `directory`.
        let inode = match self.path_table.get(path){
            Some(i) => {
                // If file exists and `excl` is set, return `Exist` error.
                if oflags.contains(OpenFlags::EXCL) {
                    return Err(ErrNo::Exist);
                }
                i.clone()
            },
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
        // Truacate the file if `trunc` flag is set.
        if oflags.contains(OpenFlags::TRUNC) {
            info!("call path_open trunc flag");
            // Check the right of the program on truacate
            if !principal_right.contains(Rights::PATH_FILESTAT_SET_SIZE) {
                return Err(ErrNo::Access);
            }
            let inode_impl = self.inode_table.get_mut(&inode).ok_or(ErrNo::NoEnt)?;
            inode_impl.raw_file_data = Vec::new();
            inode_impl.file_stat.file_size = 0u64;
        }
        let new_fd = self.new_fd()?;
        let FileStat{file_type, file_size, .. } = self
            .inode_table
            .get(&inode)
            .ok_or(ErrNo::BadF)?.file_stat;
        let fd_stat = FdStat {
            file_type,
            flags,
            rights_base,
            rights_inheriting,
        };
        self.file_table.insert(
            new_fd,
            FileTableEntry {
                inode,
                fd_stat,
                offset: 0,
                advice: vec![(0, file_size, Advice::Normal)],
            },
        );
        info!("new fd {:?} created for {:?}.",new_fd, path);
        Ok(new_fd)
    }

    /// The stub implementation of `path_readlink`. Return unsupported error `NoSys`.
    /// We only support the searching from the root Fd.
    #[inline]
    pub(crate) fn path_readlink(&mut self, fd: Fd, path: impl AsRef<str>) -> FileSystemError<Vec<u8>> {
        info!("call path_readlink on fd {:?}, path {:?}", fd, path.as_ref());
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
    pub(crate) fn path_remove_directory(&mut self, fd: Fd, path: impl AsRef<str>) -> FileSystemError<()> {
        info!("call path_remove_directory on fd {:?}, path {:?}", fd, path.as_ref());
        self.check_right(&fd, Rights::PATH_REMOVE_DIRECTORY)?;
        // ONLY allow search on the root for now.
        if fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_rename`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_rename(
        &mut self,
        old_fd: Fd,
        old_path: impl AsRef<str>,
        new_fd: Fd,
        new_path: impl AsRef<str>,
    ) -> FileSystemError<()> {
        info!("call path_rename on old fd {:?}, old path {:?}, new fd {:?}, new path: {:?}", old_fd, old_path.as_ref(), new_fd, new_path.as_ref());
        self.check_right(&old_fd, Rights::PATH_RENAME_SOURCE)?;
        self.check_right(&new_fd, Rights::PATH_RENAME_TARGET)?;
        Err(ErrNo::NoSys)
    }

    /// Get random bytes.
    pub(crate) fn random_get(&self, buf_len: Size) -> FileSystemError<Vec<u8>> {
        let mut buf = vec![0; buf_len as usize];
       if let result::Result::Success = getrandom(&mut buf) {
            Ok(buf)
        } else {
            Err(ErrNo::NoSys)
        }
    }

    /// The stub implementation of `path_rename`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_link(
        &mut self,
        old_fd: Fd,
        old_flag: LookupFlags,
        old_path: impl AsRef<str>,
        new_fd: Fd,
        new_path: impl AsRef<str>,
    ) -> FileSystemError<()> {
        info!("call path_link on fd {:?}, flag {:?}, old path {:?}, new fd {:?}, new path: {:?}", old_fd, old_flag, old_path.as_ref(), new_fd, new_path.as_ref());
        self.check_right(&old_fd, Rights::PATH_LINK_SOURCE)?;
        self.check_right(&new_fd, Rights::PATH_LINK_TARGET)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_symlink`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_symlink(
        &mut self,
        old_path: impl AsRef<str>,
        fd: Fd,
        new_path: impl AsRef<str>,
    ) -> FileSystemError<()> {
        info!("call path_symlink on old path {:?}, fd {:?}, new path: {:?}", old_path.as_ref(), fd, new_path.as_ref());
        self.check_right(&fd, Rights::PATH_SYMLINK)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_unlink_file`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_unlink_file(
        &mut self,
        fd: Fd,
        path: impl AsRef<str>,
    ) -> FileSystemError<()> {
        info!("call path_symlink on fd {:?}, path {:?}", fd, path.as_ref());
        self.check_right(&fd, Rights::PATH_UNLINK_FILE)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `poll_oneoff`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn poll_oneoff(
        &mut self,
        subscriptions: Vec<Subscription>,
        events: Vec<Event>,
    ) -> FileSystemError<Size> {
        info!("call path_symlink on the length subscriptions {:?}, event {:?}", subscriptions.len(), events.len());
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_recv`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_recv(
        &mut self,
        socket: Fd,
        buffer_len: usize,
        ri_flags: RiFlags,
    ) -> FileSystemError<(Vec<u8>, RoFlags)> {
        info!("call sock_recv on the socket {:?}, buffer_len {:?}, ri_flag {:?}", socket, buffer_len, ri_flags);
        self.check_right(&socket, Rights::FD_READ)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_send`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_send(
        &mut self,
        socket: Fd,
        buf: Vec<u8>,
        si_flags: SiFlags,
    ) -> FileSystemError<Size> {
        info!("call sock_recv on the socket {:?}, buffer len {:?}, si_flag {:?}", socket, buf.len(), si_flags);
        self.check_right(&socket, Rights::FD_WRITE)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_shutdown`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_shutdown(
        &mut self,
        socket: Fd,
        flags: SdFlags,
    ) -> FileSystemError<()> {
        info!("call sock_recv on the socket {:?} flag {:?}", socket, flags);
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
    pub fn write_file_by_filename(
        &mut self,
        principal: &Principal,
        file_name: impl AsRef<str>,
        data: &[u8],
        is_append: bool,
    ) -> Result<(), ErrNo> {
        let file_name = file_name.as_ref();
        info!("write_file_by_filename: {}", file_name);
        let fd = self.path_open(
            principal,
            FileSystem::ROOT_DIRECTORY_FD,
            LookupFlags::empty(),
            file_name,
            OpenFlags::CREATE | if !is_append {OpenFlags::TRUNC} else {OpenFlags::empty()},
            FileSystem::DEFAULT_RIGHTS,
            FileSystem::DEFAULT_RIGHTS,
            FdFlags::empty(),
        )?;
        if !self.file_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_base
            .contains(Rights::FD_WRITE | Rights::FD_SEEK) {
                return Err(ErrNo::Access);
        }
        if is_append { self.fd_seek(fd, 0, Whence::End)?; }
        self.fd_write(fd,data.to_vec())?;
        self.fd_close(fd)?;
        Ok(())
    }

    /// Read from a file on path `file_name`. 
    /// The `principal` must have the right on `path_open`,
    /// `fd_read` and `fd_seek`.
    pub fn read_file_by_filename(
        &mut self,
        principal: &Principal,
        file_name: impl AsRef<str>,
    ) -> Result<Vec<u8>, ErrNo> {
        let file_name = file_name.as_ref();
        info!("read_file_by_filename: {}", file_name);
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
        if !self.file_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_base
            .contains(Rights::FD_READ | Rights::FD_SEEK) {
                return Err(ErrNo::Access);
        }
        let file_stat = self.fd_filestat_get(fd)?;
        let rst = self.fd_read(fd,file_stat.file_size as usize)?;
        self.fd_close(fd)?;
        Ok(rst)
    }

    /// Get the maximum right associated to the principal on the file
    fn get_right(&self, principal: &Principal, file_name : &str) -> FileSystemError<Rights> {
        self.right_table
            .get(principal)
            .ok_or(ErrNo::Access)?
            .get(file_name)
            .map(|r| r.clone())
            .ok_or(ErrNo::Access)
    }
}
