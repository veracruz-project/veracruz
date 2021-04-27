//! A synthetic filesystem.
//!
//! This virtual file system(VFS) for Veracruz runtime and execution engine.
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

use std::{collections::HashMap, convert::TryFrom, string::ToString, string::String, vec::Vec};
use wasi_types::{
    Advice, DirCookie, DirEnt, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, Inode,
    LookupFlags, OpenFlags, Prestat, Rights, Size, Whence, Device, Timestamp, FileType,
    PreopenType
};
use veracruz_utils::policy::principal::{RightTable, Principal};

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
/// TODO: ref vs concrete parameter in wasi api !?
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
    /// Digest table. Certain files must match the digest before writting to the filesystem.
    digest_table: HashMap<String, String>
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
    pub const DEFAULT_RIGHTS: Rights = Rights::from_bits_truncate(Rights::FD_DATASYNC.bits() | Rights::FD_READ.bits() | Rights::FD_SEEK.bits() | Rights::FD_FDSTAT_SET_FLAGS.bits() | Rights::FD_SYNC.bits() | Rights::FD_TELL.bits() | Rights::FD_WRITE.bits() | Rights::FD_ADVISE.bits() | Rights::FD_ALLOCATE.bits() | Rights::PATH_CREATE_DIRECTORY.bits() | Rights::PATH_CREATE_FILE.bits() | Rights::PATH_LINK_SOURCE.bits() | Rights::PATH_LINK_TARGET.bits() | Rights::PATH_OPEN.bits() | Rights::PATH_READLINK.bits() | Rights::PATH_RENAME_SOURCE.bits() | Rights::PATH_RENAME_TARGET.bits() | Rights::PATH_FILESTAT_GET.bits() | Rights::FD_FILESTAT_SET_SIZE.bits() | Rights::FD_FILESTAT_SET_TIMES.bits() | Rights::PATH_SYMLINK.bits() | Rights::PATH_REMOVE_DIRECTORY.bits() | Rights::PATH_UNLINK_FILE.bits() | Rights::POLL_FD_READWRITE.bits());

    /// Creates a new, empty filesystem.
    ///
    /// TODO: the file descriptors 0, 1, and 2 are pre-allocated for stdin and
    /// similar.  Rust programs are going to expect that this is true, so we
    /// need to preallocate some files corresponding to those, here.
    #[inline]
    pub fn new(right_table : RightTable) -> Self {
        let mut rst = Self {
            file_table: HashMap::new(),
            path_table: HashMap::new(),
            inode_table: HashMap::new(),
            right_table,
            digest_table: HashMap::new(),
        };
        rst.init()
    }

    fn init(mut self) -> Self {
        // Use inode 2 as the root
        // Install directory??
        self.install_dir(Self::ROOT_DIRECTORY,&Self::ROOT_DIRECTORY_INODE);
        self.install_fd(&Self::ROOT_DIRECTORY_FD,&Self::ROOT_DIRECTORY_INODE);
        //TODO remove test stub
        self.install_file("input.txt",&(42 as u64).into(), "test content".as_bytes());
        self.install_file("stderr",&(11 as u64).into(), "".as_bytes());
        self.install_fd(&Fd(2),&(11 as u64).into());
        self
    }
    
    fn install_dir(&mut self, path : &str, inode : &Inode) {
        let file_stat = FileStat{
            device: (0 as u64).into(),
            inode : inode.clone(),
            file_type: FileType::Directory,
            num_links: 0,
            file_size : 0 as u64,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let node = InodeImpl {
            file_stat,
            // TODO introduce dir structure.
            raw_file_data : Vec::new(),
        };
        self.inode_table.insert(inode.clone(),node);
        self.path_table.insert(path.to_string(),inode.clone());
    }

    fn install_file(&mut self, path : &str, inode : &Inode, raw_file_data : &[u8]) {
        let file_size = raw_file_data.len();
        let file_stat = FileStat{
            device: (0 as u64).into(),
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
        self.path_table.insert(path.to_string(),inode.clone());
    }

    fn install_fd(&mut self, fd : &Fd, inode : &Inode) {

        let fd_stat = FdStat {
            file_type : FileType::RegularFile,
            flags : FdFlags::APPEND,
            //TODO add the corresponding right.
            rights_base : Rights::FD_READ,
            rights_inheriting : Rights::FD_READ,
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

    fn next_fd(&self) -> Fd {
        // TODO: It is an insecure implementation of choosing a new FD.
        //       The new FD should be choisen randomly.
        // NOTE: the FD 0,1 and 2 are reserved to in out err.
        self
        .file_table
        .keys()
        .max()
        .map(|Fd(fd_num)| Fd(fd_num + 1))
        .unwrap_or(Fd(4))
    }

    fn next_inode(&self) -> Inode {
        // TODO: It is an insecure implementation of choosing a new Inode.
        //       The new Inode should be choisen randomly.
        // NOTE: the Inode 2 is reserved to the root.
        self
        .inode_table
        .keys()
        .max()
        .map(|Inode(inode_num)| Inode(inode_num + 1))
        .unwrap_or(Inode(3))
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
    pub(crate) fn fd_close(&mut self, fd: Fd) -> FileSystemError<()> {
        println!("call fd_close on {:?}", fd);
        self.file_table.remove(&fd).ok_or(ErrNo::BadF);
        Ok(())
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
    ) -> FileSystemError<()> {
        println!("call fd_advise on fd {:?}, offset {:?}, len {:?}, advice {:?}", fd, offset, len, adv);
        if let Some(entry) = self.file_table.get_mut(fd) {
            entry.advice.push((offset, len, adv));
            return Ok(());
        } else {
            return Err(ErrNo::BadF);
        }
    }

    /// Return a copy of the status of the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_get(&self, fd: &Fd) -> FileSystemError<FdStat> {
        println!("call fd_fdstat_get on {:?}", fd);
        self.file_table
            .get(fd)
            .map(|FileTableEntry { fd_stat, .. }| fd_stat.clone())
            .ok_or(ErrNo::BadF)
    }

    /// Change the flag associated with the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_set_flags(&mut self, fd: &Fd, flags: FdFlags) -> FileSystemError<()> {
        println!("call fd_fdstat_set_flags on {:?} and flags {:?}", fd, flags);
        self.file_table
            .get_mut(fd)
            .map(|FileTableEntry { mut fd_stat, .. }| {
                fd_stat.flags = flags;
            })
            .ok_or(ErrNo::BadF)
    }

    /// Change the right associated with the file descriptor, `fd`.
    pub(crate) fn fd_fdstat_set_rights(
        &mut self,
        fd: &Fd,
        rights_base: Rights,
        rights_inheriting: Rights,
    ) -> FileSystemError<()> {
        println!("call fd_fdstat_set_rights on {:?} and right base {:?} and inheriting {:?}", fd,rights_base, rights_inheriting);
        self.file_table
            .get_mut(fd)
            .map(|FileTableEntry { mut fd_stat, .. }| {
                fd_stat.rights_base = rights_base;
                fd_stat.rights_inheriting = rights_inheriting;
            })
            .ok_or(ErrNo::BadF)
    }

    /// Return a copy of the status of the open file pointed by the file descriptor, `fd`.
    pub(crate) fn fd_filestat_get(&self, fd: &Fd) -> FileSystemError<FileStat> {
        println!("call fd_filestat_get on {:?}", fd);
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
    pub(crate) fn fd_filestat_set_size(&mut self, fd: &Fd, size: FileSize) -> FileSystemError<()> {
        println!("call fd_filestat_set_size on {:?}", fd);
        let inode = self.file_table.get(fd).map(|FileTableEntry { inode, .. }| inode.clone()).ok_or(ErrNo::BadF)?;

        if let Some(inode) = self.inode_table.get_mut(&inode) {
            inode.file_stat.file_size = size;
            inode.raw_file_data.resize(size as usize, 0);
            return Ok(());
        } else {
            return Err(ErrNo::BadF);
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
        println!("call fd_pread_base on fd {:?} buffer_len {:?} and offset {:?}", fd, buffer_len, offset);
        let inode = self
            .file_table
            .get(fd)
            .map(|FileTableEntry { inode, .. }| inode)
            .ok_or(ErrNo::BadF)?;
        // NOTE: It should be safe to convert a u64 to usize.
        let offset = *offset as usize;

        self.inode_table
            .get(inode)
            .map(
                |InodeImpl {
                     raw_file_data: buffer,
                     ..
                 }| {
                    let (_, to_read) = buffer.split_at(offset);
                    println!("call fd_pread_base on content {:?}",to_read.len());
                    let segment = vec![buffer_len, to_read.len()];
                    let read_length = segment.iter().min().unwrap_or(&0);
                    println!("call fd_pread_base on read_length {:?}",read_length);
                    let (rst, _) = to_read.split_at(*read_length);
                    println!("call fd_pread_base result {:?}",rst.len());
                    rst.to_vec()
                },
            )
            .ok_or(ErrNo::BadF)
    }

    pub(crate) fn fd_prestat_get(&mut self, fd: &Fd) -> FileSystemError<Prestat> {
        println!("call fd_prestat_get on {:?}",fd);
        // Only support ONE preopen on Fd(3)
        if fd != &(3 as u32).into() {
            return Err(ErrNo::BadF);
        }

        let resource_type =  PreopenType::Dir {
            name_len : Self::ROOT_DIRECTORY.len() as u32
        };

        Ok(Prestat{
            resource_type 
        })
    }

    pub(crate) fn fd_prestat_dir_name(&mut self, fd: &Fd) -> FileSystemError<String> {
        // Only support ONE preopen on Fd(3)
        if fd != &(3 as u32).into() {
            return Err(ErrNo::BadF);
        }
        Ok(Self::ROOT_DIRECTORY.to_string())
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
        println!("call fd_pwrite_base on fd {:?}, offset {:?} and buf {:?}", fd, offset, buf.len());
        let inode = self
            .file_table
            .get(fd)
            .map(|FileTableEntry { inode, .. }| inode)
            .ok_or(ErrNo::BadF)?;

        if let Some(inode_impl) = self.inode_table.get_mut(inode) {
            println!("call fd_pwrite_base before: {:?}",inode_impl.raw_file_data.len());
            let remain_length = (inode_impl.file_stat.file_size - offset) as usize;
            let offset = offset as usize;
            if remain_length <= buf.len() {
                println!("call fd_pwrite_base grows length");
                let mut grow_vec = vec![0; buf.len() - remain_length];
                inode_impl.raw_file_data.append(&mut grow_vec);
            }
            let rst = buf.len();
            inode_impl.raw_file_data[offset..(offset + rst)].copy_from_slice(&buf);
            inode_impl.file_stat.file_size = inode_impl.raw_file_data.len() as u64;
            println!("call fd_pwrite_base result: {:?}",inode_impl.raw_file_data.len());
            return Ok(rst as Size);
        } else {
            return Err(ErrNo::BadF);
        }
    }

    pub(crate) fn fd_read_base(&mut self, fd: &Fd, len: usize) -> FileSystemError<Vec<u8>> {
        println!("call fd_read_base on {:?}", fd);
        let offset = if let Some(entry) = self.file_table.get(fd) {
            entry.offset
        } else {
            return Err(ErrNo::BadF);
        };
        println!("call fd_read_base current offset {:?}", offset);

        let rst = self.fd_pread_base(fd, len, &offset)?;
        self.fd_seek(fd, rst.len() as i64, Whence::Current)?;
        Ok(rst)
    }

    pub(crate) fn fd_readdir(
        &mut self,
        fd: &Fd,
        _cookie: &DirCookie,
    ) -> FileSystemError<Vec<DirEnt>> {
        println!("call fd_readdir on {:?}", fd);
        unimplemented!()
    }

    /// Atomically renumbers the `old_fd` to the `new_fd`.  Note that as
    /// Chihuahua is single-threaded this is atomic from the WASM program's
    /// point of view.
    pub(crate) fn fd_renumber(&mut self, old_fd: &Fd, new_fd: Fd) -> ErrNo {
        println!("call fd_renumber on {:?}", old_fd);
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
        println!("call fd_seek on fd {:?}, offset {:?} and whence {:?}", fd, offset, whence);
        let (inode, cur_file_offset) = match self.file_table.get(fd) {
            Some(FileTableEntry {
                // Use temporary variable `o` 
                // to reduce the ambiguity with 
                // the function parameter `offset`.
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

        println!("call fd_seek on file_size {:?}, base {:?}", file_size, new_base_offset);

        // NOTE: Ensure the computation does not overflow.
        let new_offset: FileSize = if offset >= 0 {
            // It is safe to convert a positive i64 to u64.
            let t_offset = new_base_offset + (offset.abs() as u64);
            // Offset is allowed to equal to file size
            if t_offset > file_size {
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

        println!("call fd_seek on new offset {:?}", new_offset);

        // Update the offset
        if let Some(entry) = self.file_table.get_mut(fd) {
            entry.offset = new_offset;
        } else {
            return Err(ErrNo::BadF);
        };

        Ok(new_offset)
    }

    /// Returns the current offset associated with the file descriptor.
    pub(crate) fn fd_tell(&self, fd: &Fd) -> FileSystemError<FileSize> {
        if let Some(entry) = self.file_table.get(fd) {
            Ok(entry.offset.clone())
        } else {
            Err(ErrNo::BadF)
        }
    }

    pub(crate) fn fd_write_base(&mut self, fd: &Fd, buf: Vec<u8>) -> FileSystemError<Size> {
        println!("call fd_write_base on {:?}", fd);
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
        _flags: &LookupFlags,
        path: &String,
    ) -> FileSystemError<FileStat> {
        let inode = self.path_table.get(path).ok_or(ErrNo::NoEnt)?.clone();
        self.inode_table
            .get(&inode)
            .map(|InodeImpl { file_stat, .. }| file_stat.clone())
            .ok_or(ErrNo::BadF)
    }

    /// Open a file or directory on behalf of the principal `principal`.
    /// TODO: It provides the minimum functionality of opening a file.
    ///       Finish the rest functionality required the WASI spec.
    pub(crate) fn path_open(
        &mut self,
        principal : &Principal,
        // The parent fd for searching
        fd: &Fd,
        _dirflags: LookupFlags,
        path: &str,
        oflags: OpenFlags,
        rights_base: Rights,
        rights_inheriting: Rights,
        flags: FdFlags,
    ) -> FileSystemError<Fd> {
        println!("call path_open, on behalf of {:?}, on fd {:?}, on dir {:?} with open_flag {}, right_base {:?}, rights_inheriting {:?} and fd_flag {:?}",
            fd, principal, path, oflags.bits(), rights_base, rights_inheriting, flags);
        // Read the right related to the principal.
        let principal_right = if *principal != Principal::InternalSuperUser {
            self.get_right(&principal, path)?
        } else {
            Rights::all()
        };
        // Check the right of the program on path_open
        if !principal_right.contains(Rights::PATH_OPEN) {
            return Err(ErrNo::Access);
        }
        let rights_base = rights_base & principal_right;
        let rights_inheriting = rights_inheriting & principal_right;
        println!("call path_open, the right {:?} and inheriting right {:?}",
            rights_base, rights_inheriting);
        // ONLY allow search on the root for now.
        if *fd != Self::ROOT_DIRECTORY_FD {
            return Err(ErrNo::NotDir);
        }
        // TODO IMPL oflags logic
        let inode = match self.path_table.get(path){
            Some(i) => i.clone(),
            None => {
                println!("call path_open create");
                if !oflags.contains(OpenFlags::CREATE) {
                    return Err(ErrNo::NoEnt);
                }
                let new_inode = self.next_inode();
                self.install_file(path, &new_inode, &vec![]);
                new_inode
            }
        };
        println!("call path_open find the inode {:?}", inode);

        if oflags.contains(OpenFlags::TRUNC) {
            self.inode_table.get_mut(&inode).map(|inode_impl|{
                println!("call path_open trunc");
                inode_impl.raw_file_data = Vec::new();
                inode_impl.file_stat = FileStat{
                    device: (0 as u64).into(),
                    inode : inode.clone(),
                    file_type: FileType::Directory,
                    num_links: 0,
                    file_size : 0 as u64,
                    atime: Timestamp::from_nanos(0),
                    mtime: Timestamp::from_nanos(0),
                    ctime: Timestamp::from_nanos(0),
                };
            });
        }
        let next_fd = self.next_fd();
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
        println!("new fd {:?} created for {:?}.",next_fd, path);
        Ok(next_fd)
    }

    pub(crate) fn path_remove_directory(&mut self, _fd: &Fd, _path: &String) -> ErrNo {
        unimplemented!()
    }

    pub(crate) fn path_rename(
        &mut self,
        _old_fd: &Fd,
        _old_path: &String,
        _new_fd: &Fd,
        _new_path: String,
    ) -> ErrNo {
        unimplemented!()
    }

    pub fn write_file_by_filename(
        &mut self,
        principal: &Principal,
        file_name: &str,
        data: &[u8],
    ) -> Result<(), ErrNo> {
        println!("write_file_by_filename: {}", file_name);
        let fd = self.path_open(
            principal,
            &FileSystem::ROOT_DIRECTORY_FD,
            LookupFlags::SYMLINK_FOLLOW,
            file_name,
            OpenFlags::CREATE,
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
        self.fd_write_base(&fd,data.to_vec())?;
        self.fd_close(fd)?;
        Ok(())
    }

    pub fn read_file_by_filename(
        &mut self,
        principal: &Principal,
        file_name: &str,
    ) -> Result<Vec<u8>, ErrNo> {
        println!("read_file_by_filename: {}", file_name);
        let fd = self.path_open(
            principal,
            &FileSystem::ROOT_DIRECTORY_FD,
            LookupFlags::SYMLINK_FOLLOW,
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
        let file_stat = self.fd_filestat_get(&fd)?;
        let rst = self.fd_read_base(&fd,file_stat.file_size as usize)?;
        self.fd_close(fd)?;
        Ok(rst)
    }


    /// Compute the digest of a `buffer`
    fn sha_256_digest(buffer: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, buffer)
            .as_ref()
            .to_vec()
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
