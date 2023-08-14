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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(clippy::too_many_arguments)]

use crate::native_module_manager::NativeModuleManager;
use policy_utils::{
    principal::{FileRights, NativeModule, NativeModuleType, Principal, RightsTable},
    CANONICAL_STDERR_FILE_PATH, CANONICAL_STDIN_FILE_PATH, CANONICAL_STDOUT_FILE_PATH,
};
use std::{
    boxed::Box,
    cmp::min,
    collections::HashMap,
    convert::{AsRef, TryFrom},
    fmt::Debug,
    path::{Component, Path, PathBuf},
    string::String,
    sync::{Arc, Mutex, MutexGuard},
    vec::Vec,
};
use log::error;
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
};
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

/// Internal shared inode table.
type SharedInodeTable = Arc<Mutex<InodeTable>>;

////////////////////////////////////////////////////////////////////////////////
// INodes.
////////////////////////////////////////////////////////////////////////////////

/// INodes wrap the actual raw file data, and associate meta-data with that raw
/// data buffer.
#[derive(Clone, Debug)]
struct InodeEntry {
    /// The status of this file.
    file_stat: FileStat,
    /// The content of the inode.
    data: InodeImpl,
}

impl InodeEntry {
    /// Resize a file to `size`, fill with `fill_byte` if it grows,
    /// and update the file status.
    /// Return ErrNo::IsDir, if it is not a file
    #[inline]
    pub(self) fn resize_file(&mut self, size: FileSize, fill_byte: u8) -> FileSystemResult<()> {
        self.data.resize_file(size, fill_byte)?;
        self.file_stat.file_size = size;
        Ok(())
    }

    /// Read maximum `max` bytes from the offset `offset`.
    /// Return ErrNo::IsDir if it is not a file.
    #[inline]
    pub(self) fn read_file(&self, buf: &mut [u8], offset: FileSize) -> FileSystemResult<usize> {
        self.data.read_file(buf, offset)
    }

    /// Write `buf` to the file from the offset `offset`,
    /// update the file status and return the number of written bytes.
    /// Otherwise, return ErrNo::IsDir if it is not a file.
    #[inline]
    pub(self) fn write_file(&mut self, buf: &[u8], offset: FileSize) -> FileSystemResult<usize> {
        let rst = self.data.write_file(buf, offset)?;
        self.file_stat.file_size = self.data.len()?;
        Ok(rst)
    }

    /// Truncate the file.
    /// Return ErrNo::IsDir if it is not a file.
    #[inline]
    pub(self) fn truncate_file(&mut self) -> FileSystemResult<()> {
        self.data.truncate_file()?;
        self.file_stat.file_size = 0u64;
        Ok(())
    }

    /// Insert a file to the directory at `self`.
    /// Return ErrNo:: NotDir if `self` is not a directory.
    #[inline]
    pub(self) fn insert<T: AsRef<Path>>(&mut self, path: T, inode: Inode) -> FileSystemResult<()> {
        self.data.insert(path, inode)
    }

    /// Return the inode of `path`.
    /// Return ErrNo:: NotDir if `self` is not a directory.
    #[inline]
    pub(self) fn get_inode_by_path<T: AsRef<Path>>(&self, path: T) -> FileSystemResult<Inode> {
        self.data.get_inode_by_path(path)
    }

    /// Check if the inode is a directory
    #[inline]
    pub(crate) fn is_dir(&self) -> bool {
        self.data.is_dir()
    }

    /// Read metadata of all files and sub-dirs in the dir and return a vec of DirEnt,
    /// or return NotDir if `self` is not a dir
    #[inline]
    pub(self) fn read_dir(
        &self,
        inode_table: &InodeTable,
    ) -> FileSystemResult<Vec<(DirEnt, Vec<u8>)>> {
        self.data.read_dir(inode_table)
    }

    /// Return the number of bytes, if it is a file,
    /// or the number of inodes, if it is a directory.
    #[inline]
    pub(self) fn len(&self) -> FileSystemResult<FileSize> {
        self.data.len()
    }

    /// Return if the current path corresponds is a service.
    #[inline]
    pub(self) fn is_service(&self) -> bool {
        self.data.is_service()
    }

    /// Return the service handler, and the current content of in the special file.
    #[inline]
    pub(crate) fn service_handler(
        &self,
    ) -> FileSystemResult<(Arc<Mutex<Box<NativeModule>>>, Vec<u8>)> {
        self.data.service_handler()
    }
}

/// The actual data of an inode, either a file or a directory.
#[derive(Clone, Debug)]
enum InodeImpl {
    /// A special file that is bound to a native service.
    /// Writing to the file triggers the execution of the service.
    /// It treat the `Inode` as the input parameter and the result will be stored in Vec.
    /// The services will use the FileSystem (handle) to access the VFS.
    /// NOTE: Current design is only safe for SINGLE thread.
    ///     - The program is allowed to read the (input) content to the service; and the input
    ///     information, might be sensitive, is cleaned on the invocation `fd_closed`.
    ///     In single thread situation, it is fine.
    ///     - The output of the service is determined by the service itself. It can try to open
    ///     any file and write to it, as long as the service has enough capabilities in FileSystem.
    NativeModule(Arc<Mutex<Box<NativeModule>>>, Vec<u8>),
    /// A file
    File(Vec<u8>),
    /// A directory. The `PathBuf` key is the relative path and must match the name inside the `Inode`.
    Directory(HashMap<PathBuf, Inode>),
}

impl InodeImpl {
    const CURRENT_PATH_STR: &'static str = ".";
    const PARENT_PATH_STR: &'static str = "..";

    /// Return a new Directory InodeImpl containing only current and parent paths
    pub(crate) fn new_directory(current: Inode, parent: Inode) -> Self {
        let mut dir = HashMap::new();
        dir.insert(PathBuf::from(Self::CURRENT_PATH_STR), current);
        dir.insert(PathBuf::from(Self::PARENT_PATH_STR), parent);
        Self::Directory(dir)
    }

    /// Resize a file to `size`, and fill with `fill_byte` if it grows.
    /// Otherwise, return ErrNo::IsDir if it is not a file.
    #[inline]
    pub(self) fn resize_file(&mut self, size: FileSize, fill_byte: u8) -> FileSystemResult<()> {
        match self {
            Self::NativeModule(.., file) | Self::File(file) => {
                file.resize(<_>::try_from_or_errno(size)?, fill_byte);
                Ok(())
            }
            Self::Directory(_) => Err(ErrNo::IsDir),
        }
    }

    /// Read maximum `max` bytes from the offset `offset`.
    /// Otherwise, return ErrNo::IsDir if it is a dir
    /// or ErrNo::Again if it is a service and no output is available.
    pub(self) fn read_file(&self, buf: &mut [u8], offset: FileSize) -> FileSystemResult<usize> {
        match self {
            Self::File(b) | Self::NativeModule(.., b) => {
                Self::read_bytes_from_offset(b, buf, offset)
            }
            Self::Directory(_) => Err(ErrNo::IsDir),
        }
    }

    fn read_bytes_from_offset(
        bytes: &[u8],
        buf: &mut [u8],
        offset: FileSize,
    ) -> FileSystemResult<usize> {
        // NOTE: It should be safe to convert a u64 to usize.
        let offset = <_>::try_from_or_errno(offset)?;
        //          offset
        //             v
        // ---------------------------------------------
        // |  ....     | to_read              |        |
        // ---------------------------------------------
        //             v ...  read_length ... v
        //             ------------------------
        //             | rst                  |
        //             ------------------------
        let (_, to_read) = bytes.split_at(offset);
        let read_length = min(buf.len(), to_read.len());
        buf[..read_length].copy_from_slice(&to_read[..read_length]);
        Ok(read_length)
    }

    /// Write `buf` to the file from the offset `offset` and return the number of written bytes.
    /// Otherwise, return ErrNo::IsDir if it is not a file.
    pub(self) fn write_file(&mut self, buf: &[u8], offset: FileSize) -> FileSystemResult<usize> {
        let bytes = match self {
            Self::File(b) | Self::NativeModule(.., b) => b,
            Self::Directory(_) => return Err(ErrNo::IsDir),
        };
        // NOTE: It should be safe to convert a u64 to usize.
        let offset = <_>::try_from_or_errno(offset)?;
        //          offset
        //             v  .. remain_length .. v
        // ----------------------------------------------
        // |  ....     | to_write             0 0 ...   |
        // ----------------------------------------------
        //             v     ...    buf.len()    ...    v
        //             ----------------------------------
        //             | buf                            |
        //             ----------------------------------
        if offset + buf.len() > bytes.len() {
            bytes.resize(offset + buf.len(), 0);
        }
        let write_length = buf.len();
        bytes[offset..(offset + write_length)].copy_from_slice(&buf);
        Ok(write_length)
    }

    /// Truncate the file.
    /// Return ErrNo::IsDir if it is a dir.
    #[inline]
    pub(self) fn truncate_file(&mut self) -> FileSystemResult<()> {
        match self {
            Self::File(b) | Self::NativeModule(.., b) => {
                b.clear();
                Ok(())
            }
            Self::Directory(_) => Err(ErrNo::IsDir),
        }
    }

    /// Insert a file to the directory at `self`.
    /// Return ErrNo:: NotDir if `self` is not a directory.
    #[inline]
    pub(self) fn insert<T: AsRef<Path>>(&mut self, path: T, inode: Inode) -> FileSystemResult<()> {
        match self {
            InodeImpl::Directory(path_table) => {
                path_table.insert(path.as_ref().to_path_buf(), inode)
            }
            _otherwise => return Err(ErrNo::NotDir),
        };
        Ok(())
    }

    /// Insert a file to the directory at `self`.
    /// Return ErrNo:: NotDir if `self` is not a directory.
    #[inline]
    pub(self) fn get_inode_by_path<T: AsRef<Path>>(&self, path: T) -> FileSystemResult<Inode> {
        match self {
            InodeImpl::Directory(path_table) => {
                Ok(*path_table.get(path.as_ref()).ok_or(ErrNo::NoEnt)?)
            }
            _otherwise => Err(ErrNo::NotDir),
        }
    }

    /// Return the number of the bytes, if it is a file,
    /// or the number of inodes, if it it is a directory.
    #[inline]
    pub(self) fn len(&self) -> FileSystemResult<FileSize> {
        let rst = match self {
            Self::NativeModule(.., f) | Self::File(f) => f.len(),
            Self::Directory(f) => f.len(),
        };
        Ok(rst as FileSize)
    }

    /// Check if it is a directory
    #[inline]
    pub(crate) fn is_dir(&self) -> bool {
        match self {
            Self::Directory(_) => true,
            _ => false,
        }
    }

    /// Check if it is a service
    #[inline]
    pub(crate) fn is_service(&self) -> bool {
        match self {
            Self::NativeModule(..) => true,
            _ => false,
        }
    }

    /// Return the service.
    #[inline]
    pub(crate) fn service_handler(
        &self,
    ) -> FileSystemResult<(Arc<Mutex<Box<NativeModule>>>, Vec<u8>)> {
        match self {
            Self::NativeModule(service, input) => {
                // NOTE: We copy out, particularly `input`, on purpose, as they are protected by a
                // lock on the inote table. We have to release the lock allowing the service to
                // access the FileSystem, unless we introduce lock ownership transition mechanism.
                // A better way to organising the inode is using fine-grained locper entry
                Ok((service.clone(), input.clone()))
            }
            _ => Err(ErrNo::Inval),
        }
    }

    /// Read metadata of files in the dir and return a vec of DirEnt,
    /// or return NotDir if `self` is not a dir
    pub(self) fn read_dir(
        &self,
        inode_table: &InodeTable,
    ) -> FileSystemResult<Vec<(DirEnt, Vec<u8>)>> {
        let dir = match self {
            InodeImpl::Directory(d) => d,
            _otherwise => return Err(ErrNo::NotDir),
        };
        let mut rst = Vec::new();
        for (index, (path, inode)) in dir.iter().enumerate() {
            let path_byte = path.as_os_str().as_bytes().to_vec();
            let dir_ent = DirEnt {
                next: (u64::try_from_or_errno(index)? + 1u64).into(),
                inode: *inode,
                name_len: <_>::try_from_or_errno(path_byte.len())?,
                file_type: inode_table.get(&inode)?.file_stat.file_type,
            };
            rst.push((dir_ent, path_byte))
        }
        Ok(rst)
    }
}

struct InodeTable {
    /// All inodes
    table: HashMap<Inode, InodeEntry>,
    /// The Right table for Principal, including participants and programs.
    /// It will be used to create a new FileSystem (handler).
    rights_table: RightsTable,
    /// The inodes for stdin, stdout and stderr, respectively.
    stdin: Inode,
    stdout: Inode,
    stderr: Inode,
    /// We allocate inodes in the same way as we allocate file descriptors. Inode's are 64 bits
    /// rather than 31 bits, so the artificial limit on inode allocations is 2^64.
    next_inode_candidate: Inode,
}

impl Debug for InodeTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Inode Table:\n")?;
        for (k, v) in self.table.iter() {
            match &v.data {
                InodeImpl::File(_) => write!(f, "\t{:?} -> file\n", k)?,
                InodeImpl::NativeModule(service, _) => write!(
                    f,
                    "\t{:?} -> service {}\n",
                    k,
                    service
                        .try_lock()
                        .map_or_else(|_| "(failed to lock)".to_string(), |o| format!("{:?}", o))
                )?,
                InodeImpl::Directory(d) => write!(f, "\t{:?} -> {:?}\n", k, d)?,
            }
        }
        Ok(())
    }
}

impl InodeTable {
    /// The root directory name. It will be pre-opened for any wasm program.
    pub(self) const ROOT_DIRECTORY: &'static str = "/";
    /// The root directory inode. It will be pre-opened for any wasm program.
    /// File descriptors 0 to 2 are reserved for the standard streams.
    pub(self) const ROOT_DIRECTORY_INODE: Inode = Inode(2);

    fn new(rights_table: RightsTable) -> FileSystemResult<Self> {
        let mut rst = Self {
            table: HashMap::new(),
            stdin: Inode(0),
            stdout: Inode(1),
            stderr: Inode(2),
            rights_table,
            next_inode_candidate: Inode(Self::ROOT_DIRECTORY_INODE.0 + 1),
        };
        // Add the root directory
        rst.add_dir(
            Self::ROOT_DIRECTORY_INODE,
            Path::new(Self::ROOT_DIRECTORY),
            Self::ROOT_DIRECTORY_INODE,
        )?;
        // Add the standard in out and err.
        rst.install_standard_streams_inode()?;
        Ok(rst)
    }

    /// Install static and dynamic native modules.
    /// Assume `path` is an absolute path to a (special) file.
    /// NOTE: this function is intended to be called after the root filesystem (handler) is
    /// created.
    fn install_services(&mut self, native_modules: Vec<NativeModule>) -> FileSystemResult<()> {
        for native_module in native_modules {
            let path = match native_module.r#type() {
                NativeModuleType::Static { special_file } => Some(special_file),
                NativeModuleType::Dynamic { special_file, .. } => Some(special_file),
                _ => None,
            };
            if path.is_some() {
                let path = path.unwrap();
                let service = Arc::new(Mutex::new(Box::new(native_module.clone())));
                let new_inode = self.new_inode()?;
                let path = strip_root_slash_path(path);
                // Call the existing function to create general files.
                self.add_file(Self::ROOT_DIRECTORY_INODE, path, new_inode, Vec::new())?;
                // Manually uplift the general file to special file bound with the service.
                self.table.get_mut(&new_inode).ok_or(ErrNo::Inval)?.data =
                    InodeImpl::NativeModule(service, Vec::new());
            }
        }
        Ok(())
    }

    /// Install standard streams (`stdin`, `stdout`, `stderr`).
    fn install_standard_streams_inode(&mut self) -> FileSystemResult<()> {
        self.stdin = self.new_inode()?;
        self.add_file(
            self.stdin,
            CANONICAL_STDIN_FILE_PATH,
            self.stdin,
            Vec::new(),
        )?;

        self.stdout = self.new_inode()?;
        self.add_file(
            self.stdout,
            CANONICAL_STDOUT_FILE_PATH,
            self.stdout,
            Vec::new(),
        )?;

        self.stderr = self.new_inode()?;
        self.add_file(
            self.stderr,
            CANONICAL_STDERR_FILE_PATH,
            self.stderr,
            Vec::new(),
        )?;
        Ok(())
    }

    /// Return the inode for stdin
    #[inline]
    fn stdin(&self) -> Inode {
        self.stdin
    }

    /// Return the inode for stdout
    #[inline]
    fn stdout(&self) -> Inode {
        self.stdout
    }

    /// Return the inode for stderr
    #[inline]
    fn stderr(&self) -> Inode {
        self.stderr
    }

    /// Insert a new inode
    #[inline]
    fn insert(&mut self, inode: Inode, entry: InodeEntry) -> FileSystemResult<()> {
        self.table.insert(inode, entry);
        Ok(())
    }

    /// Return the inode entry associated to `inode`
    #[inline]
    fn get(&self, inode: &Inode) -> FileSystemResult<&InodeEntry> {
        self.table.get(&inode).ok_or(ErrNo::NoEnt)
    }

    /// Return the inode entry associated to `inode`
    #[inline]
    fn get_mut(&mut self, inode: &Inode) -> FileSystemResult<&mut InodeEntry> {
        self.table.get_mut(&inode).ok_or(ErrNo::NoEnt)
    }

    /// Return if the `inode` is a directory.
    #[inline]
    fn is_dir(&self, inode: &Inode) -> bool {
        self.get(inode).map(|i| i.is_dir()).unwrap_or(false)
    }

    /// Return if the `inode` is an empty directory.
    #[inline]
    fn is_dir_empty(&self, inode: &Inode) -> FileSystemResult<bool> {
        let inode = self.get(inode);
        match inode.map(|i| i.is_dir()).unwrap_or(false) {
            true => Ok(inode?.read_dir(&self)?.iter().count() <= 2),
            false => Ok(false),
        }
    }

    /// Return the rights table of `principal`.
    #[inline]
    fn get_rights(&self, principal: &Principal) -> FileSystemResult<&HashMap<PathBuf, Rights>> {
        self.rights_table.get(principal).ok_or(ErrNo::Access)
    }

    /// Return the inode and the associated inode entry at the relative `path` in the parent
    /// inode `parent_inode`. Return Error if `fd` is not a directory.
    fn get_inode_by_inode_path<T: AsRef<Path>>(
        &self,
        parent_inode: &Inode,
        path: T,
    ) -> FileSystemResult<(Inode, &InodeEntry)> {
        let inode = path
            .as_ref()
            .components()
            .fold(Ok(*parent_inode), |last, component| {
                // If there is an error
                let last = last?;
                // Find the next inode
                self.get(&last)?.get_inode_by_path(component)
            })?;
        //let inode = parent_inode_entry.get_inode_by_path(path.as_ref())?;
        Ok((inode, self.get(&inode)?))
    }

    /// Pick a fresh inode.
    fn new_inode(&mut self) -> FileSystemResult<Inode> {
        let cur = self.next_inode_candidate;
        // Consume all possible Inodes, or the next inode is already used.
        if self.table.contains_key(&cur) {
            return Err(ErrNo::NFile);
        }
        // NOTE: we waste the max inode.
        self.next_inode_candidate = match u64::from(cur).checked_add(1) {
            Some(next) => Inode(next),
            None => return Err(ErrNo::NFile), // Not quite accurate, but this may be the best fit
        };
        Ok(cur)
    }

    /// Install a directory with inode `new_inode` and attach it under the parent inode `parent`.
    /// The `new_inode` MUST be fresh.
    fn add_dir<T: AsRef<Path>>(
        &mut self,
        parent: Inode,
        path: T,
        new_inode: Inode,
    ) -> FileSystemResult<()> {
        let file_stat = FileStat {
            device: (0u64).into(),
            inode: new_inode,
            file_type: FileType::Directory,
            num_links: 0,
            file_size: 0u64,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let path = path.as_ref().to_path_buf();
        let node = InodeEntry {
            file_stat,
            data: InodeImpl::new_directory(new_inode, parent),
        };
        // NOTE: first add the inode to its parent inode, in the case of parent is not a directory,
        // it causes error and no side effect will be made to the file system, i.e no island inode.
        // If parent is not equal to new_inode, it means `new_inode` is not a ROOT,
        // Hence, add the new inode into the parent inode dir.
        if parent != new_inode {
            self.table
                .get_mut(&parent)
                .ok_or(ErrNo::NoEnt)?
                .insert(path, new_inode)?;
        }
        // Add the map from the new inode to inode implementation.
        self.insert(new_inode, node)?;
        Ok(())
    }

    /// Create all directories in the `path`, if necessary, e.g. `/path/to/a/new/dir`.
    /// The last component in `path` will be treated a directory rather a file.
    fn add_all_dir<T: AsRef<Path>>(
        &mut self,
        mut parent: Inode,
        path: T,
    ) -> FileSystemResult<Inode> {
        // iterate over the path and create the directory if necessary.
        for component in path.as_ref().components() {
            if let Component::Normal(c) = component {
                let new_parent = match self.get_inode_by_inode_path(&parent, c) {
                    Ok((o, _)) => o,
                    // Directory is not exist, hence create it.
                    Err(ErrNo::NoEnt) => {
                        let new_inode = self.new_inode()?;
                        self.add_dir(parent, c, new_inode)?;
                        new_inode
                    }
                    Err(e) => return Err(e),
                };
                parent = new_parent;
            } else {
                return Err(ErrNo::Inval);
            }
        }
        Ok(parent)
    }

    /// Install a file with content `raw_file_data` and attach it to `inode`.
    /// Create any missing directory in the path.
    fn add_file<T: AsRef<Path>>(
        &mut self,
        parent: Inode,
        path: T,
        new_inode: Inode,
        raw_file_data: Vec<u8>,
    ) -> FileSystemResult<()> {
        let path = path.as_ref();
        // Create missing directories in the `parent` inode if the path contains directory,
        // and shift the `parent` to the direct parent of the new file.
        // Note that if the parent() return None, it means an empty `path` is passed in, hence it
        // is an error.
        let (parent, path) = {
            let parent_path = path.parent().ok_or(ErrNo::Inval)?;
            // No parent, directly add it
            if parent_path == Path::new("") {
                (parent, path)
            } else {
                let file_path = path.file_name().map(|s| s.as_ref()).ok_or(ErrNo::Inval)?;
                self.add_all_dir(parent, parent_path)?;
                (
                    self.get_inode_by_inode_path(&parent, parent_path)?.0,
                    file_path,
                )
            }
        };
        let file_size = raw_file_data.len();
        let file_stat = FileStat {
            device: 0u64.into(),
            inode: new_inode,
            file_type: FileType::RegularFile,
            num_links: 0,
            file_size: <_>::try_from_or_errno(file_size)?,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let node = InodeEntry {
            file_stat,
            data: InodeImpl::File(raw_file_data),
        };
        // Add the map from the new inode to inode implementation.
        self.insert(new_inode, node)?;
        // Add the new inode into the parent inode dir. If the parent == new_inode, it may be
        // special inode, e.g. stdin stdout stderr
        if parent != new_inode {
            self.table
                .get_mut(&parent)
                .ok_or(ErrNo::NoEnt)?
                .insert(path, new_inode)?;
        }
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
// File-table entries.
////////////////////////////////////////////////////////////////////////////////

/// Each file table entry contains an index into the inode table, pointing to an
/// `InodeEntry`, where the static file data is stored.
#[derive(Clone, Debug)]
struct FdEntry {
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
    fd_table: HashMap<Fd, FdEntry>,
    /// In order to quickly allocate file descriptors, we keep track of a monotonically increasing
    /// candidate, starting just above the reserved values. With this approach, file descriptors
    /// can not be re-allocated after being freed, imposing an artificial limit of 2^31 file
    /// descriptor allocations over the course of a program's execution.
    next_fd_candidate: Fd,
    /// The inode table, which points to the actual data associated with a file
    /// and other metadata.  This table is indexed by the Inode.
    inode_table: SharedInodeTable,
    /// Preopen FD table. Mapping the FD to dir name.
    prestat_table: HashMap<Fd, PathBuf>,
    /// A list of native modules available for the computation.
    native_modules: Vec<NativeModule>,
}

impl Debug for FileSystem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\tFD table:\n")?;
        for (fd, fd_entry) in self.fd_table.iter() {
            write!(f, "\t\t{:?} -> {:?}\n", fd, fd_entry)?;
        }
        write!(f, "\tpre open fd paths:\n")?;
        for (fd, path) in self.fd_table.iter() {
            write!(f, "\t\t{:?} -> {:?}\n", fd, path)?;
        }
        Ok(())
    }
}

impl FileSystem {
    ////////////////////////////////////////////////////////////////////////////
    // Creating filesystems.
    ////////////////////////////////////////////////////////////////////////////

    /// The first file descriptor. It will be pre-opened for any Wasm program.
    pub const FIRST_FD: Fd = Fd(3);
    /// The default initial rights on a newly created file.
    pub const DEFAULT_RIGHTS: Rights = Rights::all();

    /// Creates a new, empty `Filesystem` and returns the superuser handle, which
    /// has all the capabilities on the entire filesystem.
    ///
    /// NOTE: the file descriptors `0`, `1`, and `2` are pre-allocated for `stdin`
    /// and similar with respect to the parameter `std_streams_table`.  Userspace
    /// Wasm programs are going to expect that this is true, so we need to
    /// preallocate some files corresponding to those, here.
    pub fn new(
        rights_table: RightsTable,
        native_modules: Vec<NativeModule>,
    ) -> FileSystemResult<Self> {
        let mut rst = Self {
            fd_table: HashMap::new(),
            next_fd_candidate: Self::FIRST_FD,
            inode_table: Arc::new(Mutex::new(InodeTable::new(rights_table)?)),
            prestat_table: HashMap::new(),
            native_modules: native_modules.to_vec(),
        };

        let mut all_rights = HashMap::new();
        all_rights.insert(PathBuf::from("/"), Rights::all());
        all_rights.insert(PathBuf::from(CANONICAL_STDIN_FILE_PATH), Rights::all());
        all_rights.insert(PathBuf::from(CANONICAL_STDOUT_FILE_PATH), Rights::all());
        all_rights.insert(PathBuf::from(CANONICAL_STDERR_FILE_PATH), Rights::all());

        rst.install_prestat::<PathBuf>(&all_rights)?;

        rst.install_services(native_modules)?;

        Ok(rst)
    }

    /// This is the *only* public API to create a new `FileSystem` (handler).
    /// It returns a `FileSystem` where directories are pre-opened with appropriate
    /// capabilities in relation to a principal, `principal`. Native modules are
    /// inherited from the parent `FileSystem`.
    pub fn spawn(&self, principal: &Principal) -> FileSystemResult<Self> {
        let mut rst = Self {
            fd_table: HashMap::new(),
            next_fd_candidate: Self::FIRST_FD,
            inode_table: self.inode_table.clone(),
            prestat_table: HashMap::new(),
            native_modules: self.native_modules.to_vec(),
        };

        // Must clone as `install_prestat` needs to lock the `inode_table` too
        let rights_table = self.lock_inode_table()?.get_rights(principal)?.clone();
        rst.install_prestat::<PathBuf>(&rights_table)?;

        Ok(rst)
    }

    #[inline]
    fn service_fs(&self) -> FileSystemResult<Self> {
        Ok(self.clone())
    }

    /// Create a dummy filesystem
    #[allow(dead_code)]
    pub(crate) fn new_dummy() -> Self {
        let mut rights_table = HashMap::new();
        rights_table.insert(Principal::NoCap, HashMap::new());
        Self {
            fd_table: HashMap::new(),
            next_fd_candidate: Self::FIRST_FD,
            inode_table: Arc::new(Mutex::new(InodeTable::new(rights_table).unwrap())),
            prestat_table: HashMap::new(),
            native_modules: Vec::new(),
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal auxiliary methods
    ////////////////////////////////////////////////////////////////////////

    /// Lock the inode table
    #[inline]
    fn lock_inode_table(&self) -> FileSystemResult<MutexGuard<InodeTable>> {
        self.inode_table.lock().map_err(|_| ErrNo::Busy)
    }

    /// Install standard streams (`stdin`, `stdout`, `stderr`).
    fn install_standard_streams_fd(
        &mut self,
        std_streams_table: &[FileRights],
    ) -> FileSystemResult<()> {
        for std_stream in std_streams_table {
            // Map each standard stream to an fd and inode.
            // Rights are assumed to be already configured by the execution engine in the rights table
            // at that point.
            // Base rights are ignored and replaced with the default rights

            let (fd_number, inode_number) = match std_stream.file_name() {
                CANONICAL_STDIN_FILE_PATH => (Fd(0), self.lock_inode_table()?.stdin()),
                CANONICAL_STDOUT_FILE_PATH => (Fd(1), self.lock_inode_table()?.stdout()),
                CANONICAL_STDERR_FILE_PATH => (Fd(2), self.lock_inode_table()?.stderr()),
                _otherwise => continue,
            };
            let rights = Rights::from_bits(<_>::try_from_or_errno(*std_stream.rights())?)
                .ok_or(ErrNo::Inval)?;
            self.install_fd(
                fd_number,
                FileType::RegularFile,
                inode_number,
                &rights,
                &rights,
            );
        }
        Ok(())
    }

    /// Install `stdin`, `stdout`, `stderr`, `$ROOT`, and all dir in `dir_paths`,
    /// and then pre-open them.
    fn install_prestat<T: AsRef<Path> + std::cmp::Eq + std::hash::Hash + Sized>(
        &mut self,
        rights_table: &HashMap<T, Rights>,
    ) -> FileSystemResult<()> {
        // construct the rights for stdin stdout and stderr.
        let std_streams_table = rights_table
            .iter()
            .filter_map(|(k, v)| {
                let file = k.as_ref().to_str();
                let rights = *v;
                match file {
                    // Extract right associated to stdin stdout stderr
                    Some(path)
                        if path == CANONICAL_STDIN_FILE_PATH
                            || path == CANONICAL_STDOUT_FILE_PATH
                            || path == CANONICAL_STDERR_FILE_PATH =>
                    {
                        let rights_u32 = match u32::try_from_or_errno(u64::from(rights)) {
                            Ok(o) => o,
                            Err(_) => return None,
                        };
                        let file_rights = FileRights::new(String::from(path), rights_u32);
                        Some(file_rights)
                    }
                    _other => None,
                }
            })
            .collect::<Vec<_>>();
        // Pre open the standard streams.
        self.install_standard_streams_fd(&std_streams_table)?;

        let first_fd = Self::FIRST_FD.0;

        // Load all pre-opened directories. Create directories if necessary.
        let rights_table_without_std = rights_table.iter().filter(|(k, _)| {
            let k = k.as_ref();
            k != Path::new(CANONICAL_STDIN_FILE_PATH)
                && k != Path::new(CANONICAL_STDOUT_FILE_PATH)
                && k != Path::new(CANONICAL_STDERR_FILE_PATH)
        });
        for (index, (path, rights)) in rights_table_without_std.enumerate() {
            let new_fd = Fd(u32::try_from_or_errno(index)? + first_fd);
            let path = path.as_ref();
            // strip off the root
            let relative_path = strip_root_slash_path(path);
            let new_inode = {
                if relative_path == Path::new("") {
                    InodeTable::ROOT_DIRECTORY_INODE
                } else {
                    self.lock_inode_table()?
                        .add_all_dir(InodeTable::ROOT_DIRECTORY_INODE, relative_path)?
                }
            };
            self.install_fd(
                new_fd,
                // We use unknown here as we allow pre install either file or dir
                FileType::Unknown,
                new_inode,
                &rights,
                &rights,
            );
            self.prestat_table.insert(new_fd, path.to_path_buf());
        }
        // Set the next_fd_candidate, it might waste few FDs.
        self.next_fd_candidate = Fd(Self::FIRST_FD.0 + u32::try_from_or_errno(rights_table.len())?);

        Ok(())
    }

    fn install_services(&mut self, native_modules: Vec<NativeModule>) -> FileSystemResult<()> {
        self.lock_inode_table()?.install_services(native_modules)
    }

    /// Install a `fd` to the file system. The fd will be of type RegularFile.
    fn install_fd(
        &mut self,
        fd: Fd,
        file_type: FileType,
        inode: Inode,
        rights_base: &Rights,
        rights_inheriting: &Rights,
    ) {
        let fd_stat = FdStat {
            file_type,
            flags: FdFlags::empty(),
            rights_base: *rights_base,
            rights_inheriting: *rights_inheriting,
        };

        let fd_entry = FdEntry {
            inode,
            fd_stat,
            offset: 0,
            /// Advice on how regions of the file are to be used.
            advice: Vec::new(),
        };
        self.fd_table.insert(fd, fd_entry);
    }

    /// Pick a fresh fd.
    fn new_fd(&mut self) -> FileSystemResult<Fd> {
        let cur = self.next_fd_candidate;
        // Consume all possible FDs, or the next FD is already used.
        if u32::from(cur) & 1 << 31 != 0 || self.fd_table.contains_key(&cur) {
            return Err(ErrNo::NFile); // Not quite accurate, but this may be the best fit
        }
        self.next_fd_candidate = Fd(u32::from(cur) + 1);
        Ok(cur)
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

    /// Return the inode and the associated inode entry, contained in file descriptor `fd`
    #[inline]
    fn get_inode_by_fd(&self, fd: &Fd) -> FileSystemResult<Inode> {
        Ok(self.fd_table.get(fd).ok_or(ErrNo::BadF)?.inode)
    }

    /// Return the inode and the associated inode entry at the relative `path` in the file
    /// descriptor `fd`. Return Error if `fd` is not a directory.
    fn get_inode_by_fd_path<T: AsRef<Path>>(&self, fd: &Fd, path: T) -> FileSystemResult<Inode> {
        let parent_inode = self.get_inode_by_fd(fd)?;
        Ok(self
            .lock_inode_table()?
            .get_inode_by_inode_path(&parent_inode, path)?
            .0)
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
        let inode = self.get_inode_by_fd(&fd)?;
        // Limit the scope of the lock
        {
            let mut inode_table = self.lock_inode_table()?;
            let f = inode_table.get_mut(&inode)?;
            if f.is_service() {
                f.truncate_file()?;
            }
        }
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
        Ok(self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.fd_stat)
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

        Ok(self.lock_inode_table()?.get(&inode)?.file_stat)
    }

    /// Change the size of the open file pointed by the file descriptor, `fd`. The extra bytes are
    /// filled with ZERO.
    pub(crate) fn fd_filestat_set_size(&mut self, fd: Fd, size: FileSize) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::FD_FILESTAT_SET_SIZE)?;
        let inode = self
            .fd_table
            .get(&fd)
            .map(|FdEntry { inode, .. }| *inode)
            .ok_or(ErrNo::BadF)?;

        self.lock_inode_table()?
            .get_mut(&inode)?
            .resize_file(size, 0)
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
            .map(|FdEntry { inode, .. }| *inode)
            .ok_or(ErrNo::BadF)?;

        let mut inode_table = self.lock_inode_table()?;
        let mut inode_impl = inode_table.get_mut(&inode)?;
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
    pub(crate) fn fd_pread<B: AsMut<[u8]>>(
        &self,
        fd: Fd,
        bufs: &mut [B],
        offset: FileSize,
    ) -> FileSystemResult<usize> {
        self.check_right(&fd, Rights::FD_READ)?;
        self.fd_pread_internal(fd, bufs, offset)
    }

    /// A rust-style implementation for `fd_pread`, yet without rights check.
    /// The actual WASI spec, requires, after `fd`, an extra parameter of type IoVec,
    /// to which the content should be written.
    /// Also the WASI requires the function returns the number of byte read.
    /// However, the implementation of WASI spec of fd_pread depends on
    /// how a particular execution engine handles the memory.
    /// That is, different engines provide different API to interact the linear memory
    /// space of WASM. Hence, the method here return the read bytes as `Vec<u8>`.
    fn fd_pread_internal<B: AsMut<[u8]>>(
        &self,
        fd: Fd,
        bufs: &mut [B],
        offset: FileSize,
    ) -> FileSystemResult<usize> {
        let inode = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.inode;

        let f = self.lock_inode_table()?;
        let f = f.get(&inode)?;

        let mut offset = offset;
        let mut len = 0;
        for buf in bufs {
            let delta = f.read_file(buf.as_mut(), offset)?;
            offset += u64::try_from_or_errno(delta)?;
            len += delta;
        }

        Ok(len)
    }

    /// Return the status of a pre-opened Fd `fd`.
    #[inline]
    pub(crate) fn fd_prestat_get(&mut self, fd: Fd) -> FileSystemResult<Prestat> {
        let path = self.prestat_table.get(&fd).ok_or(ErrNo::BadF)?;
        let resource_type = PreopenType::Dir {
            name_len: <_>::try_from_or_errno(path.as_os_str().len())?,
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
    pub(crate) fn fd_pwrite<B: AsRef<[u8]>>(
        &mut self,
        fd: Fd,
        bufs: &[B],
        offset: FileSize,
    ) -> FileSystemResult<usize> {
        self.check_right(&fd, Rights::FD_WRITE)?;
        let inode = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.inode;

        //// NOTE: Careful about the lock scope.,as a service may need to lock
        //// the inode_table internally.
        let (len, is_service) = {
            let mut f = self.lock_inode_table()?;
            let f = f.get_mut(&inode)?;

            let mut offset = offset;
            let mut len = 0;
            for buf in bufs {
                let delta = f.write_file(buf.as_ref(), offset)?;
                offset += u64::try_from_or_errno(delta)?;
                len += delta;
            }
            (len, f.is_service())
        };

        // If it is a service, call it.
        // Warning: There is no input validity check performed here. It is the
        // native module's responsibility to implement that.
        if is_service {
            let (service, exec_config) = self
                .lock_inode_table()?
                .get_mut(&inode)?
                .service_handler()?;
            let native_module = service.lock().map_err(|_| ErrNo::Busy)?;

            // Invoke native module manager
            let mut native_module_manager =
                NativeModuleManager::new(*native_module.clone(), self.service_fs()?);
            // Invoke native module with execution configuration
            native_module_manager.execute(exec_config)?;
        }
        Ok(len)
    }

    /// A rust-style base implementation for `fd_read`. It directly calls `fd_pread` with the
    /// current `offset` of Fd `fd` and then calls `fd_seek`.
    pub(crate) fn fd_read<B: AsMut<[u8]>>(
        &mut self,
        fd: Fd,
        bufs: &mut [B],
    ) -> FileSystemResult<usize> {
        self.check_right(&fd, Rights::FD_READ)?;
        let offset = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset;

        let read_len = self.fd_pread(fd, bufs, offset)?;
        self.fd_seek(fd, read_len as i64, Whence::Current)?;
        Ok(read_len)
    }

    /// Function `fd_read_executable` reads an executable. This function should *only* be called
    /// internally. It directly calls `fd_pread` with the
    /// current `offset` of Fd `fd` and then calls `fd_seek`.
    pub(crate) fn fd_read_executable<B: AsMut<[u8]>>(
        &mut self,
        fd: Fd,
        bufs: &mut [B],
    ) -> FileSystemResult<usize> {
        self.check_right(&fd, Rights::FD_EXECUTE)?;
        let offset = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset;

        let read_len = self.fd_pread_internal(fd, bufs, offset)?;
        self.fd_seek(fd, read_len as i64, Whence::Current)?;
        Ok(read_len)
    }

    /// The implementation of `fd_readdir`.
    #[inline]
    pub(crate) fn fd_readdir(
        &mut self,
        fd: Fd,
        cookie: DirCookie,
    ) -> FileSystemResult<Vec<(DirEnt, Vec<u8>)>> {
        self.check_right(&fd, Rights::FD_READDIR)?;
        let dir_inode = self.get_inode_by_fd(&fd)?;
        // limit lock scope
        let mut dirs = {
            let inode_table = self.lock_inode_table()?;
            inode_table.get(&dir_inode)?.read_dir(&inode_table)?
        };
        let cookie = <_>::try_from_or_errno(cookie.0)?;
        if dirs.len() < cookie {
            return Ok(Vec::new());
        }
        let rst = dirs.split_off(cookie);
        Ok(rst)
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
        let FdEntry { inode, offset, .. } = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?;
        let file_size = self.lock_inode_table()?.get(inode)?.file_stat.file_size;

        let new_base_offset = match whence {
            Whence::Current => *offset,
            Whence::End => file_size,
            Whence::Start => 0,
        };

        // NOTE: Ensure the computation does not overflow.
        let new_offset: FileSize = if delta >= 0 {
            // It is safe to convert a positive i64 to u64.
            let t_offset = new_base_offset + u64::try_from_or_errno(delta.abs())?;
            // If offset is greater the file size, then expand the file.
            if t_offset > file_size {
                self.fd_filestat_set_size(fd, t_offset)?;
            }
            t_offset
        } else {
            // It is safe to convert a positive i64 to u64.
            if u64::try_from_or_errno(delta.abs())? > new_base_offset {
                return Err(ErrNo::SPipe);
            }
            new_base_offset - u64::try_from_or_errno(delta.abs())?
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
        Ok(self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset)
    }

    /// A rust-style base implementation for `fd_write`. It directly calls `fd_pwrite` with the
    /// current `offset` of Fd `fd` and then calls `fd_seek`.
    pub(crate) fn fd_write<B: AsRef<[u8]>>(
        &mut self,
        fd: Fd,
        bufs: &[B],
    ) -> FileSystemResult<usize> {
        self.check_right(&fd, Rights::FD_WRITE)?;
        let offset = self.fd_table.get(&fd).ok_or(ErrNo::BadF)?.offset;

        let rst = self.fd_pwrite(fd, bufs, offset)?;
        self.fd_seek(fd, rst as i64, Whence::Current)?;
        Ok(rst)
    }

    /// The implementation of `path_create_directory`.
    #[inline]
    pub(crate) fn path_create_directory<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        path: T,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::PATH_CREATE_DIRECTORY)?;
        let parent_inode = self.get_inode_by_fd(&fd)?;
        if !self.lock_inode_table()?.is_dir(&parent_inode) {
            return Err(ErrNo::NotDir);
        }
        // The path exists
        if self.get_inode_by_fd_path(&fd, path.as_ref()).is_ok() {
            return Err(ErrNo::Exist);
        }
        // Create ALL missing dir in the path
        // In each round, the `last` carries the current parent inode or an error
        // and component is the next component in the path.
        path.as_ref().components().fold(
            Ok(parent_inode),
            |last: FileSystemResult<Inode>, component| {
                // If there is an error
                let last = last?;
                let component_path = match component {
                    Component::Normal(p) => Ok(p),
                    _otherwise => Err(ErrNo::Inval),
                }?;
                let new_inode = self.lock_inode_table()?.new_inode()?;
                self.lock_inode_table()?
                    .add_dir(last, component_path, new_inode)?;
                // return the next inode, preparing for the next round.
                Ok(new_inode)
            },
        )?;
        Ok(())
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
        let inode = self.get_inode_by_fd_path(&fd, path)?;
        Ok(self.lock_inode_table()?.get(&inode)?.file_stat)
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

        let inode = self.get_inode_by_fd_path(&fd, path)?;
        let mut inode_table = self.lock_inode_table()?;
        let mut inode_impl = inode_table.get_mut(&inode)?;
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
    /// * if `DIRECTORY` is set, `path_open` fails if the path is not a directory.
    pub(crate) fn path_open<T: AsRef<Path>>(
        &mut self,
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
        // Check the right of the program on path_open
        self.check_right(&fd, Rights::PATH_OPEN)?;
        // Read the parent inode.
        let parent_inode = self.get_inode_by_fd(&fd)?;

        if !self.lock_inode_table()?.is_dir(&parent_inode) {
            return Err(ErrNo::NotDir);
        }
        // Intersect with the inheriting right from `fd`
        let fd_inheriting = self
            .fd_table
            .get(&fd)
            .ok_or(ErrNo::BadF)?
            .fd_stat
            .rights_inheriting;
        let rights_base = rights_base & fd_inheriting;
        let rights_inheriting = rights_inheriting & fd_inheriting;
        // Several oflags logic, inc. `create`, `excl` and `directory`.
        let inode = match self.get_inode_by_fd_path(&fd, path) {
            Ok(inode) => {
                // If file exists and `excl` is set, return `Exist` error.
                if oflags.contains(OpenFlags::EXCL) {
                    return Err(ErrNo::Exist);
                }
                if oflags.contains(OpenFlags::DIRECTORY) && !self.lock_inode_table()?.is_dir(&inode)
                {
                    return Err(ErrNo::NotDir);
                }
                inode
            }
            Err(e) => {
                // If file does NOT exists and `create` is NOT set, return `NoEnt` error.
                if !oflags.contains(OpenFlags::CREATE) {
                    return Err(e);
                }
                // Check the right of the program on create file
                self.check_right(&fd, Rights::PATH_CREATE_FILE)?;
                let new_inode = self.lock_inode_table()?.new_inode()?;
                self.lock_inode_table()?
                    .add_file(parent_inode, path, new_inode, Vec::new())?;
                new_inode
            }
        };
        // Truncate the file if `trunc` flag is set.
        if oflags.contains(OpenFlags::TRUNC) {
            // Check the right of the program on truncate
            self.check_right(&fd, Rights::PATH_FILESTAT_SET_SIZE)?;
            self.lock_inode_table()?.get_mut(&inode)?.truncate_file()?;
        }
        let new_fd = self.new_fd()?;
        let FileStat {
            file_type,
            file_size,
            ..
        } = self.lock_inode_table()?.get(&inode)?.file_stat;
        let fd_stat = FdStat {
            file_type,
            flags,
            rights_base,
            rights_inheriting,
        };
        self.fd_table.insert(
            new_fd,
            FdEntry {
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
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `path_remove_directory`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn path_remove_directory<T: AsRef<Path>>(
        &mut self,
        fd: Fd,
        _path: T,
    ) -> FileSystemResult<()> {
        self.check_right(&fd, Rights::PATH_REMOVE_DIRECTORY)?;
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
    pub(crate) fn sock_recv<B: AsMut<[u8]>>(
        &mut self,
        socket: Fd,
        _bufs: &[B],
        _ri_flags: RiFlags,
    ) -> FileSystemResult<(Size, RoFlags)> {
        self.check_right(&socket, Rights::FD_READ)?;
        Err(ErrNo::NoSys)
    }

    /// The stub implementation of `sock_send`. Return unsupported error `NoSys`.
    #[inline]
    pub(crate) fn sock_send<B: AsRef<[u8]>>(
        &mut self,
        socket: Fd,
        _bufs: &[B],
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

    /// This function, added for Veracruz, creates a new anonymous file.
    /// It will return an Err if getrandom fails, but perhaps in no other
    /// circumstances.
    pub(crate) fn fd_create(&mut self) -> FileSystemResult<Fd> {
        let inode = self.lock_inode_table()?.new_inode()?;
        let file_stat = FileStat {
            device: 0u64.into(),
            inode: inode.clone(),
            file_type: FileType::RegularFile,
            num_links: 0,
            file_size: 0,
            atime: Timestamp::from_nanos(0),
            mtime: Timestamp::from_nanos(0),
            ctime: Timestamp::from_nanos(0),
        };
        let node = InodeEntry {
            file_stat,
            data: InodeImpl::File(Vec::new()),
        };
        self.lock_inode_table()?.insert(inode, node)?;

        let new_fd = self.new_fd()?;
        let file_type = FileType::RegularFile;
        let flags = FdFlags::empty();
        let rights_base = Rights::all();
        let rights_inheriting = Rights::all();
        let fd_stat = FdStat {
            file_type,
            flags,
            rights_base,
            rights_inheriting,
        };
        let fd_entry = FdEntry {
            inode,
            fd_stat,
            offset: 0,
            advice: vec![(0, 0, Advice::Normal)],
        };
        self.fd_table.insert(new_fd, fd_entry);
        Ok(new_fd)
    }

    ////////////////////////////////////////////////////////////////////////
    // Public interface for the filesystem.
    // It will be used by the veracruz runtime.
    ////////////////////////////////////////////////////////////////////////

    /// Return an appropriate prestat fd for the path
    pub fn find_prestat<T: AsRef<Path>>(&self, path: T) -> Result<(Fd, PathBuf), ErrNo> {
        let path = path.as_ref();
        let (fd, parent_path) = path
            .ancestors()
            .find_map(|parent_path| {
                self.prestat_table
                    .iter()
                    .find_map(|(prestat_fd, prestat_path)| {
                        if prestat_path == parent_path {
                            Some((prestat_fd, parent_path))
                        } else {
                            None
                        }
                    })
            })
            .ok_or(ErrNo::Access)?;

        let path = path.strip_prefix(parent_path).map_err(|_| ErrNo::Inval)?;
        Ok((*fd, path.to_path_buf()))
    }

    /// Write to a file on path `file_name`. If `is_append` is set, `data` will be appended to `file_name`.
    /// Otherwise this file will be truncated. The `principal` must have the right on `path_open`,
    /// `fd_write` and `fd_seek`.
    pub fn write_file_by_absolute_path<T: AsRef<Path>>(
        &mut self,
        file_name: T,
        data: Vec<u8>,
        is_append: bool,
    ) -> Result<(), ErrNo> {
        let file_name = file_name.as_ref();
        let (fd, file_name) = self.find_prestat(file_name)?;

        let oflag = OpenFlags::CREATE
            | if !is_append {
                OpenFlags::TRUNC
            } else {
                OpenFlags::empty()
            };
        let fd = self.path_open(
            fd,
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
        self.fd_write(fd, &[data])?;
        self.fd_close(fd)?;
        Ok(())
    }

    /// Read a file on path `file_name`.
    /// The `principal` must have the right on `path_open`,
    /// `fd_read` and `fd_seek`.
    pub fn read_file_by_absolute_path<T: AsRef<Path>>(
        &mut self,
        file_name: T,
    ) -> Result<Vec<u8>, ErrNo> {
        self.read_file_by_absolute_path_internal(file_name, false)
    }

    /// Read a file on path `file_name`.
    /// The `principal` must have the right on `path_open`,
    /// `fd_read` and `fd_seek`.
    pub fn read_executable_by_absolute_path<T: AsRef<Path>>(
        &mut self,
        file_name: T,
    ) -> Result<Vec<u8>, ErrNo> {
        self.read_file_by_absolute_path_internal(file_name, true)
    }

    fn read_file_by_absolute_path_internal<T: AsRef<Path>>(
        &mut self,
        file_name: T,
        is_reading_executable: bool,
    ) -> Result<Vec<u8>, ErrNo> {
        let expected_rights = Rights::FD_SEEK
            | if is_reading_executable {
                Rights::FD_EXECUTE
            } else {
                Rights::FD_READ
            };
        let file_name = file_name.as_ref();
        let (fd, file_name) = self.find_prestat(file_name)?;
        let fd = self.path_open(
            fd,
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
            .contains(expected_rights)
        {
            error!(
                "internal read denies, expected rights {:?}",
                expected_rights
            );
            return Err(ErrNo::Access);
        }
        let file_stat = self.fd_filestat_get(fd)?;
        let mut vec = vec![0u8; file_stat.file_size as usize];
        let read_size = if is_reading_executable {
            self.fd_read_executable(fd, &mut [&mut vec[..]])?
        } else {
            self.fd_read(fd, &mut [&mut vec[..]])?
        };
        debug_assert_eq!(read_size, vec.len());
        self.fd_close(fd)?;
        Ok(vec)
    }

    /// Read all files recursively on path `path`.
    /// The `principal` must have the right on `path_open`,
    /// `fd_read` and `fd_seek`.
    pub fn read_all_files_by_absolute_path<T: AsRef<Path>>(
        &mut self,
        path: T,
    ) -> Result<Vec<(PathBuf, Vec<u8>)>, ErrNo> {
        let path = path.as_ref();
        // Convert the absolute path to relative path and then find the inode
        let inode = self
            .lock_inode_table()?
            .get_inode_by_inode_path(
                &InodeTable::ROOT_DIRECTORY_INODE,
                strip_root_slash_path(path),
            )?
            .0;
        let mut rst = Vec::new();
        if self.lock_inode_table()?.is_dir(&inode) {
            // Limit the lock scope
            let all_dir = {
                let inode_table = self.lock_inode_table()?;
                inode_table.get(&inode)?.read_dir(&inode_table)?
            };
            for (_, sub_relative_path) in all_dir.iter() {
                let sub_relative_path =
                    PathBuf::from(OsString::from_vec(sub_relative_path.to_vec()));
                // Ignore the path for current and parent directories.
                if sub_relative_path != PathBuf::from(".")
                    && sub_relative_path != PathBuf::from("..")
                {
                    let mut sub_absolute_path = path.to_path_buf();
                    sub_absolute_path.push(sub_relative_path);
                    rst.append(&mut self.read_all_files_by_absolute_path(sub_absolute_path)?);
                }
            }
        } else {
            let buf = self.read_file_by_absolute_path(path)?;
            rst.push((path.to_path_buf(), buf));
        }

        Ok(rst)
    }

    /// Similarly to `read_all_files_by_absolute_path()`, recursively read all
    /// files under the specified `path`.
    /// The `principal` must have the right on `path_open`, `fd_read` and
    /// `fd_seek`, though read errors on leaf files are tolerated.
    /// Returns two vectors:
    ///  - A list of leaf files, along with their data, that the `principal` can
    ///    read. Also includes empty directories, just in case the native module
    ///    is expecting them; in that case the associated data is set to `None`
    ///  - A list of top-level files immediately under the root. This allows the
    ///    native module manager to mount the filesystem into the sandbox, since
    ///    Sandbox2 doesn't allow mapping a directory to `/`.
    /// This function is used by the native module manager to duplicate the
    /// VFS before running native modules.
    pub fn read_all_files_and_dirs_by_absolute_path<T: AsRef<Path>>(
        &mut self,
        path: T,
    ) -> Result<(Vec<(PathBuf, Option<Vec<u8>>)>, Vec<PathBuf>), ErrNo> {
        let path = path.as_ref();
        // Ignore special files. This avoids permission errors and deadlocks
        // when respectively reading and writing to special files.
        if path == PathBuf::from("/services") {
            return Ok((vec![], vec![]));
        }
        // Convert the absolute path to relative path and then find the inode
        let inode = self
            .lock_inode_table()?
            .get_inode_by_inode_path(
                &InodeTable::ROOT_DIRECTORY_INODE,
                strip_root_slash_path(path),
            )?
            .0;
        let mut rst = Vec::new();
        let mut top_level_files = Vec::new();
        if self.lock_inode_table()?.is_dir(&inode) {
            // Limit the lock scope
            let (all_dir, is_dir_empty) = {
                let inode_table = self.lock_inode_table()?;
                let inode_entry = inode_table.get(&inode)?;
                (
                    inode_entry.read_dir(&inode_table)?,
                    inode_table.is_dir_empty(&inode),
                )
            };
            if is_dir_empty? {
                // Directory is empty (current and parent directories don't
                // count)
                rst.push((path.to_path_buf(), None));
            } else {
                for (_, sub_relative_path) in all_dir.iter() {
                    let sub_relative_path =
                        PathBuf::from(OsString::from_vec(sub_relative_path.to_vec()));
                    // Ignore the path for current and parent directories.
                    if sub_relative_path != PathBuf::from(".")
                        && sub_relative_path != PathBuf::from("..")
                    {
                        let mut sub_absolute_path = path.to_path_buf();
                        sub_absolute_path.push(sub_relative_path);
                        let (mut list, _) =
                            self.read_all_files_and_dirs_by_absolute_path(&sub_absolute_path)?;
                        rst.append(&mut list);
                        if path == Path::new("/") {
                            top_level_files.push(sub_absolute_path);
                        }
                    }
                }
            }
        } else {
            // Ignore unreadable files
            match self.read_file_by_absolute_path(path) {
                Ok(b) => rst.push((path.to_path_buf(), Some(b))),
                Err(_) => (),
            }
        }

        Ok((rst, top_level_files))
    }

    /// Check if a `file_name` exists.
    /// Note: this function *has* side effect!
    /// It will try to open the file and then close it.
    pub fn file_exists<T: AsRef<Path>>(&mut self, file_name: T) -> Result<bool, ErrNo> {
        let file_name = file_name.as_ref();
        let (fd, file_name) = self.find_prestat(file_name)?;
        match self.path_open(
            fd,
            LookupFlags::empty(),
            file_name,
            OpenFlags::empty(),
            FileSystem::DEFAULT_RIGHTS,
            FileSystem::DEFAULT_RIGHTS,
            FdFlags::empty(),
        ) {
            Ok(new_fd) => {
                self.fd_close(new_fd)?;
                Ok(true)
            }
            Err(ErrNo::Access) => Err(ErrNo::Access),
            Err(_) => Ok(false),
        }
    }

    /// A public API for writing to stdin.
    #[inline]
    pub fn write_stdin(&mut self, buf: &[u8]) -> FileSystemResult<usize> {
        self.fd_write(Fd(0), &[buf])
    }

    /// A public API for reading from stdout.
    #[inline]
    pub fn read_stdout(&mut self) -> FileSystemResult<Vec<u8>> {
        self.read_std_stream(Fd(1))
    }

    /// A public API for writing to stdout.
    #[inline]
    pub fn write_stdout(&mut self, buf: &[u8]) -> FileSystemResult<usize> {
        self.fd_write(Fd(1), &[buf])
    }

    /// A public API for reading from stderr.
    #[inline]
    pub fn read_stderr(&mut self) -> FileSystemResult<Vec<u8>> {
        self.read_std_stream(Fd(2))
    }

    /// A public API for writing to stderr.
    #[inline]
    pub fn write_stderr(&mut self, buf: &[u8]) -> FileSystemResult<usize> {
        self.fd_write(Fd(2), &[buf])
    }

    /// Read from std streaming.
    fn read_std_stream(&mut self, fd: Fd) -> FileSystemResult<Vec<u8>> {
        // read the length of a stream
        let inode = self.get_inode_by_fd(&fd)?;
        let len = self.lock_inode_table()?.get(&inode)?.len()?;
        let mut vec = vec![0u8; len as usize];
        let read_len = self.fd_read(fd, &mut [&mut vec[..]])?;
        debug_assert_eq!(read_len, vec.len());
        Ok(vec)
    }

    /// Return whether the given path can be executed by the given principal.
    /// Since files inherit their parent's rights, granting execution to a
    /// parent directory is enough to grant execution to every file under it.
    /// Fails if the principal can't access the path with `path_open()`.
    pub fn is_executable<T: AsRef<Path>>(
        &mut self,
        principal: &Principal,
        path: T,
    ) -> FileSystemResult<bool> {
        let path = path.as_ref();
        let mut vfs = self.spawn(principal)?;

        // Open path on behalf of the principal
        let (fd, file_name) = vfs.find_prestat(path)?;
        let fd = vfs.path_open(
            fd,
            LookupFlags::empty(),
            file_name,
            OpenFlags::empty(),
            FileSystem::DEFAULT_RIGHTS,
            FileSystem::DEFAULT_RIGHTS,
            FdFlags::empty(),
        )?;

        vfs.check_right(&fd, Rights::FD_EXECUTE)?;

        Ok(true)
    }
}

pub(crate) trait TryFromOrErrNo<T>: Sized {
    fn try_from_or_errno(t: T) -> FileSystemResult<Self>;
}

impl<T, U> TryFromOrErrNo<T> for U
where
    U: TryFrom<T> + Sized,
{
    fn try_from_or_errno(t: T) -> FileSystemResult<Self> {
        Self::try_from(t).map_err(|_| ErrNo::Inval)
    }
}

pub(crate) fn strip_root_slash_path(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

pub(crate) fn strip_root_slash_str(path: &str) -> &str {
    match &path[0..1] {
        "/" => &path[1..],
        _ => path,
    }
}
