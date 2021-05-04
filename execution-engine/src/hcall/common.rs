//! Common code for any implementation of WASI:
//! - An interface for handling memory access.
//! - An interface for executing a program.
//! - A WASI Wrapper. it wraps the strictly type WASI-like API
//! in the virtual file system. It convert wasm u32-based parameters to 
//! properly typed parameters and rust-style error handling to 
//! c-style returning code. 
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(non_camel_case_types)]

use err_derive::Error;
use serde::{Deserialize, Serialize};
use wasi_types::{
    Advice, DirCookie, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, LookupFlags,
    OpenFlags, Prestat, Rights, Size, Whence, IoVec, DirEnt, Pointer
};
use veracruz_utils::policy::principal::Principal;
use std::{
    convert::TryFrom,
    fmt::{Display, Error, Formatter},
    mem::size_of,
    slice::from_raw_parts,
    string::{String, ToString},
    vec::Vec,
};
use crate::fs::FileSystem;
#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Arc, Mutex};
#[cfg(feature = "sgx")]
use std::sync::{Arc, SgxMutex as Mutex};

////////////////////////////////////////////////////////////////////////////////
// Common constants.
////////////////////////////////////////////////////////////////////////////////

/// List of WASI API.
#[derive(Debug, PartialEq, Clone, FromPrimitive, ToPrimitive, Serialize, Deserialize)]
pub enum WASIAPIName {
    ARGS_GET = 1,
    ARGS_SIZES_GET,
    ENVIRON_GET,
    ENVIRON_SIZES_GET,
    CLOCK_RES_GET,
    CLOCK_TIME_GET,
    FD_ADVISE,
    FD_ALLOCATE,
    FD_CLOSE,
    FD_DATASYNC,
    FD_FDSTAT_GET,
    FD_FDSTAT_SET_FLAGS,
    FD_FDSTAT_SET_RIGHTS,
    FD_FILESTAT_GET,
    FD_FILESTAT_SET_SIZE,
    FD_FILESTAT_SET_TIMES,
    FD_PREAD,
    FD_PRESTAT_GET,
    FD_PRESTAT_DIR_NAME,
    FD_PWRITE,
    FD_READ,
    FD_READDIR,
    FD_RENUMBER,
    FD_SEEK,
    FD_SYNC,
    FD_TELL,
    FD_WRITE,
    PATH_CREATE_DIRECTORY,
    PATH_FILESTAT_GET,
    PATH_FILESTAT_SET_TIMES,
    PATH_LINK,
    PATH_OPEN,
    PATH_READLINK,
    PATH_REMOVE_DIRECTORY,
    PATH_RENAME,
    PATH_SYMLINK,
    PATH_UNLINK_FILE,
    POLL_ONEOFF,
    PROC_EXIT,
    PROC_RAISE,
    SCHED_YIELD,
    RANDOM_GET,
    SOCK_RECV,
    SOCK_SEND,
    SOCK_SHUTDOWN,
}

impl TryFrom<&str> for WASIAPIName {
    type Error = ();
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let rst = match s {
            "args_get" => WASIAPIName::ARGS_GET,
            "args_sizes_get" => WASIAPIName::ARGS_SIZES_GET,
            "environ_get" => WASIAPIName::ENVIRON_GET,
            "environ_sizes_get" => WASIAPIName::ENVIRON_SIZES_GET,
            "clock_res_get" => WASIAPIName::CLOCK_RES_GET,
            "clock_time_get" => WASIAPIName::CLOCK_TIME_GET,
            "fd_advise" => WASIAPIName::FD_ADVISE,
            "fd_allocate" => WASIAPIName::FD_ALLOCATE,
            "fd_close" => WASIAPIName::FD_CLOSE,
            "fd_datasync" => WASIAPIName::FD_DATASYNC,
            "fd_fdstat_get" => WASIAPIName::FD_FDSTAT_GET,
            "fd_fdstat_set_flags" => WASIAPIName::FD_FDSTAT_SET_FLAGS,
            "fd_fdstat_set_rights" => WASIAPIName::FD_FDSTAT_SET_RIGHTS,
            "fd_filestat_get" => WASIAPIName::FD_FILESTAT_GET,
            "fd_filestat_set_size" => WASIAPIName::FD_FILESTAT_SET_SIZE,
            "fd_filestat_set_times" => WASIAPIName::FD_FILESTAT_SET_TIMES,
            "fd_pread" => WASIAPIName::FD_PREAD,
            "fd_prestat_get" => WASIAPIName::FD_PRESTAT_GET,
            "fd_prestat_dir_name" => WASIAPIName::FD_PRESTAT_DIR_NAME,
            "fd_pwrite" => WASIAPIName::FD_PWRITE,
            "fd_read" => WASIAPIName::FD_READ,
            "fd_readdir" => WASIAPIName::FD_READDIR,
            "fd_renumber" => WASIAPIName::FD_RENUMBER,
            "fd_seek" => WASIAPIName::FD_SEEK,
            "fd_sync" => WASIAPIName::FD_SYNC,
            "fd_tell" => WASIAPIName::FD_TELL,
            "fd_write" => WASIAPIName::FD_WRITE,
            "path_create_directory" => WASIAPIName::PATH_CREATE_DIRECTORY,
            "path_filestat_get" => WASIAPIName::PATH_FILESTAT_GET,
            "path_filestat_set_times" => WASIAPIName::PATH_FILESTAT_SET_TIMES,
            "path_link" => WASIAPIName::PATH_LINK,
            "path_open" => WASIAPIName::PATH_OPEN,
            "path_readlink" => WASIAPIName::PATH_READLINK,
            "path_remove_directory" => WASIAPIName::PATH_REMOVE_DIRECTORY,
            "path_rename" => WASIAPIName::PATH_RENAME,
            "path_symlink" => WASIAPIName::PATH_SYMLINK,
            "path_unlink_file" => WASIAPIName::PATH_UNLINK_FILE,
            "poll_oneoff" => WASIAPIName::POLL_ONEOFF,
            "proc_exit" => WASIAPIName::PROC_EXIT,
            "proc_raise" => WASIAPIName::PROC_RAISE,
            "sched_yield" => WASIAPIName::SCHED_YIELD,
            "random_get" => WASIAPIName::RANDOM_GET,
            "sock_recv" => WASIAPIName::SOCK_RECV,
            "sock_send" => WASIAPIName::SOCK_SEND,
            "sock_shutdown" => WASIAPIName::SOCK_SHUTDOWN,
            _otherwise => return Err(()),
        };
        Ok(rst)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Miscellanea that doesn't fit elsewhere.
////////////////////////////////////////////////////////////////////////////////

/// Computes a SHA-256 digest of the bytes passed to it in `buffer`.
pub(crate) fn sha_256_digest(buffer: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, buffer)
        .as_ref()
        .to_vec()
}

/// A generic function that takes any reference to a sized type and returns a
/// byte-representation of that type.
unsafe fn pack_sized_as_bytes<T>(element: &T) -> Vec<u8>
where
    T: Sized,
{
    println!("pack_sized_as_bytes: {}",size_of::<T>());
    let slice: &[u8] = from_raw_parts((element as *const T) as *const u8, size_of::<T>());

    slice.to_vec()
}

/// Packs an `FdStat` type into a vector of bytes.  For writing `FdStat`
/// structures into memory, across the ABI boundary.
#[inline]
pub(crate) fn pack_fdstat(fdstat: &FdStat) -> Vec<u8> {
    unsafe { pack_sized_as_bytes(fdstat) }
}

/// Packs a `FileStat` type into a vector of bytes.  For writing `FileStat`
/// structures into memory, across the ABI boundary.
#[inline]
pub(crate) fn pack_filestat(stat: &FileStat) -> Vec<u8> {
    unsafe { pack_sized_as_bytes(stat) }
}

/// Packs a `PreStat` type into a vector of bytes.  For writing `PreStat`
/// structures into memory, across the ABI boundary.
#[inline]
pub(crate) fn pack_prestat(stat: &Prestat) -> Vec<u8> {
    unsafe { pack_sized_as_bytes(stat) }
}

/// Packs a `DirEnt` type into a vector of bytes.  For writing `DirEnt`
/// structures into memory, across the ABI boundary.
#[inline]
pub(crate) fn pack_dirent(dirent: &DirEnt) -> Vec<u8> {
    unsafe { pack_sized_as_bytes(dirent) }
}

//TODO RUST DOC
pub trait MemoryHandler {
    //NOTE we purposely choose u32 here as the execution engine is likely received u32 as
    //parameters
    fn write_buffer(&mut self, address: u32, buffer: &[u8]) -> ErrNo;
    fn read_buffer(&self, address: u32, length: u32) -> Result<Vec<u8>, ErrNo>;

    /// Reads a null-terminated C-style string from the runtime state's memory,
    /// starting at base address `address`.  If it fails, return ErrNo.
    ///
    /// TODO: should this not be OsStr rather than a valid UTF-8 string?  Most
    /// POSIX-style implementations allow arbitrary nonsense filenames/paths and
    /// do not mandate valid UTF-8.  How "real" do we really want to be, here?
    fn read_cstring(&self, address: u32, length: u32) -> Result<String, ErrNo> {
        let bytes = self.read_buffer(address, length)?;
        // TODO: erase the debug code
        let rst = String::from_utf8(bytes).map_err(|_e| ErrNo::IlSeq)?;
        println!("read_cstring: {}",rst);
        Ok(rst)
    }

    /// Performs a scattered read from several locations, as specified by a list
    /// of `IoVec` structures, `scatters`, from the runtime state's memory.
    fn read_iovec_scattered(&self, scatters: &[IoVec]) -> Result<Vec<Vec<u8>>, ErrNo> {
        // TODO: erase the debug code
        println!("called read_iovec_scattered: {:?}",scatters);
        let mut rst = Vec::new();
        for IoVec{buf, len} in scatters.iter(){
            rst.push(self.read_buffer(*buf, *len)?)
        }
        Ok(rst)
    }

    /// Reads a list of `IoVec` structures from a byte buffer.  Fails if reading of
    /// any `IoVec` fails, for any reason.
    fn unpack_iovec_array(&self, iovec_ptr: u32, iovec_count: u32) -> Result<Vec<IoVec>, ErrNo> {
        let iovec_bytes = self.read_buffer(iovec_ptr, iovec_count * 8)?;
        let mut iovecs = Vec::new();

        for bytes in iovec_bytes.chunks(8) {
            if bytes.len() != 8 {
                return Err(ErrNo::Inval);
            }

            let mut buf_bytes: [u8; 4] = Default::default();
            let mut len_bytes: [u8; 4] = Default::default();
            buf_bytes.copy_from_slice(&bytes[0..4]);
            len_bytes.copy_from_slice(&bytes[4..8]);
            let buf = u32::from_le_bytes(buf_bytes);
            let len = u32::from_le_bytes(len_bytes);    

            iovecs.push(IoVec{ buf, len });
        }
        // TODO: erase the debug code
        println!("unpack_iovec_array rst {:?}",iovecs);
        Ok(iovecs)
    }
}

////////////////////////////////////////////////////////////////////////////////
// The host runtime state.
////////////////////////////////////////////////////////////////////////////////

/// A wrapper on VFS for WASI, which provides common API used by wasm execution engine.
#[derive(Clone)]
pub struct WASIWrapper {
    /// The synthetic filesystem associated with this machine.
    filesystem: Arc<Mutex<FileSystem>>,
    /// The environment variables that have been passed to this program from the
    /// global policy file.  These are stored as a key-value mapping from
    /// variable name to value.
    environment_variables: Vec<(String, String)>,
    /// The array of program arguments that have been passed to this program,
    /// again from the global policy file.
    program_arguments: Vec<String>,
    /// The principal that accesses the filesystem. This information is used in path_open.
    principal: Principal,
}

/// A macro for lock the VFS in WASIWrapper and store the result in the variable, 
/// which will be captured by `$vfs` in the macro.
/// It is assumed that `self` is a WASIWrapper.
/// If the locks fails, it returns Busy error code.
macro_rules! lock_vfs {
    ($vfs:ident) => {
        match $vfs.filesystem.lock() {
            Ok(o) => o,
            Err(_) => return ErrNo::Busy,
        }
    }
}

impl WASIWrapper {

    /// The name of the WASM program's entry point.
    pub(crate) const ENTRY_POINT_NAME: &'static str = "_start";
    /// The name of the WASM program's linear memory.
    pub(crate) const LINEAR_MEMORY_NAME: &'static str = "memory";
    /// The name of the containing module for all WASI imports.
    pub(crate) const WASI_SNAPSHOT_MODULE_NAME: &'static str = "wasi_snapshot_preview1";

    ////////////////////////////////////////////////////////////////////////////
    // Creating and modifying runtime states.
    ////////////////////////////////////////////////////////////////////////////
    
    /// Creates a new initial `HostProvisioningState`.
    pub fn new(
        filesystem: Arc<Mutex<FileSystem>>,
        principal: Principal,
    ) -> Self {
        Self { 
            filesystem,
            environment_variables : Vec::new(),
            program_arguments : Vec::new(),
            principal,
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // The program's environment.
    ////////////////////////////////////////////////////////////////////////////

    /// Implementation of the WASI `args_sizes_get` function.
    pub(crate) fn args_sizes_get(&self) -> (Size, Size) {
        let argc = self.program_arguments.len();
        let size: usize = self
            .program_arguments
            .iter()
            .map(|s| s.as_bytes().len())
            .sum();

        (argc as Size, size as Size)
    }

    /// Implementation of the WASI `args_get` function.  Returns a list of
    /// program arguments encoded as bytes.
    #[inline]
    pub(crate) fn args_get(&self) -> Vec<Vec<u8>> {
        let mut buffer = Vec::new();

        for arg in self.program_arguments.iter() {
            let arg = format!("{}\0", arg);
            let bytes = arg.into_bytes();
            buffer.push(bytes);
        }

        buffer.reverse();

        buffer
    }

    /// Registers a new environment variable, `key`, with a particular value,
    /// `value`, in the program's environment.  Returns `None` iff the key was
    /// already associated with a value (in which case the key-value pair are
    /// not registered in the environment), and `Some(state)`, for `state` a
    /// modified runtime state with the pair registered, otherwise.
    pub(super) fn register_environment_variable<U>(&mut self, key: U, value: U) -> Option<&mut Self>
    where
        U: Into<String>,
    {
        let keys: Vec<String> = self
            .environment_variables
            .iter()
            .map(|(k, _v)| k)
            .cloned()
            .collect();

        let k = key.into();

        if keys.contains(&k) {
            None
        } else {
            self.environment_variables.push((k, value.into()));
            Some(self)
        }
    }

    /// Implementation of the WASI `environ_sizes_get` function.
    pub(crate) fn environ_sizes_get(&self,memory_ref: &mut impl MemoryHandler, address_for_counts: u32, address_for_buffer_size: u32) -> ErrNo {
        println!("environ_sizes_get is called");
        let environc = self.environment_variables.len() as u32;
        let mut environ_buf_size = 0usize;

        for (key, value) in self.environment_variables.iter() {
            let entry = format!("{}={}\0", key, value);
            environ_buf_size += entry.as_bytes().len();
        }

        let rst = memory_ref.write_buffer(address_for_counts, &u32::to_le_bytes(environc));
        if rst != ErrNo::Success {
            return rst;
        }
        memory_ref.write_buffer(address_for_buffer_size, &u32::to_le_bytes(environ_buf_size as u32))
    }

    /// Implementation of the WASI `environ_get` function.
    pub(crate) fn environ_get(&self, memory_ref: &mut impl MemoryHandler, mut address_for_result: u32, mut address_for_result_len: u32) -> ErrNo {
        println!("environ_get is called");

        let buffer = self.environment_variables.iter().map(|(key,value)| {
            let environ = format!("{}={}\0", key, value);
            environ.into_bytes()
        }).collect::<Vec<_>>();

        for environ in buffer {
            let length = environ.len() as u32;
            let rst_buf = memory_ref.write_buffer(address_for_result, &environ);
            if rst_buf != ErrNo::Success {
                return rst_buf;
            }
            let rst_len = memory_ref.write_buffer(address_for_result_len, &u32::to_le_bytes(length));
            if rst_len != ErrNo::Success {
                return rst_len;
            }
            address_for_result += length;
            address_for_result_len += 4;
        }

        ErrNo::Success
    }

    ////////////////////////////////////////////////////////////////////////////
    // Filesystem operations.
    ////////////////////////////////////////////////////////////////////////////

    #[inline]
    pub(crate) fn fd_close(&mut self, fd: u32) -> ErrNo {
        let mut fs = lock_vfs!(self);
        match fs.fd_close(fd.into()) {
            Ok(_) => ErrNo::Success,
            Err(e) => e,
        }
    }

    #[inline]
    pub(crate) fn fd_advise(
        &mut self,
        fd: &Fd,
        offset: FileSize,
        len: FileSize,
        advice: Advice,
    ) -> ErrNo {
        let mut fs = lock_vfs!(self);
        if let Err(err) = fs.fd_advise(fd, offset, len, advice) {
            return err;
        }
        return ErrNo::Success;
    }

    #[inline]
    pub(crate) fn fd_fdstat_get(&self, fd: &Fd) -> ErrNo {
        let mut fs = lock_vfs!(self);
        match fs.fd_fdstat_get(fd)  {
            //TODO fill in
            Ok(o) => ErrNo::Success,
            Err(e) => e,
        }
    }

    #[inline]
    pub(crate) fn fd_fdstat_set_flags(&mut self, fd: &Fd, flags: FdFlags) -> ErrNo {
        let mut fs = lock_vfs!(self);
        if let Err(err) = fs.fd_fdstat_set_flags(fd, flags) {
            return err;
        }
        return ErrNo::Success;
    }

    #[inline]
    pub(crate) fn fd_fdstat_set_rights(
        &mut self,
        fd: &Fd,
        rights_base: Rights,
        rights_inheriting: Rights,
    ) -> ErrNo {
        let mut fs = lock_vfs!(self);
        if let Err(err) = fs
            .fd_fdstat_set_rights(fd, rights_base, rights_inheriting) {
            return err;
        }
        return ErrNo::Success;
    }

    #[inline]
    pub(crate) fn fd_filestat_get(&self, fd: &Fd) -> ErrNo {
        let mut fs = lock_vfs!(self);
        match fs.fd_filestat_get(fd)  {
            //TODO fill in
            Ok(o) => ErrNo::Success,
            Err(e) => e,
        }
    }

    #[inline]
    pub(crate) fn fd_filestat_set_size(&mut self, fd: &Fd, size: FileSize) -> ErrNo {
        let mut fs = lock_vfs!(self);
        if let Err(err) = fs.fd_filestat_set_size(fd, size) {
            return err;
        }
        return ErrNo::Success;
    }

    #[inline]
    pub(crate) fn fd_prestat_get(&mut self, memory_ref: &mut impl MemoryHandler, fd: u32, address: u32) -> ErrNo {
        let fd = Fd(fd);
        let mut fs = lock_vfs!(self);
        match fs.fd_prestat_get(&fd.into()) { 
            Ok(result) => memory_ref.write_buffer(address, &pack_prestat(&result)),
            Err(err) => err
        }
    }

    #[inline]
    pub(crate) fn fd_prestat_dir_name(&mut self, memory_ref: &mut impl MemoryHandler, fd: u32, address: u32, size: u32) -> ErrNo {
        let size = size as usize;
        let mut fs = lock_vfs!(self);
        let result = match fs.fd_prestat_dir_name(&fd.into()) {
            Ok(o) => o,
            Err(e) => return e,
        };

        if result.len() > size as usize {
            return ErrNo::NameTooLong;
        }

        memory_ref.write_buffer(address, &result.into_bytes())
    }

    #[inline]
    pub(crate) fn fd_read(&mut self, memory_ref: &mut impl MemoryHandler, fd: u32, iovec_base: u32, iovec_count: u32, address: u32) -> ErrNo {

        let iovecs = match memory_ref.unpack_iovec_array(iovec_base, iovec_count) {
            Ok(o) => o,
            Err(e) => return e,
        };

        let mut size_read = 0;
        for iovec in iovecs.iter() {
            let mut fs = lock_vfs!(self);
            let to_write = match fs.fd_read_base(&fd.into(), iovec.len as usize){
                Ok(o) => o,
                Err(e) => return e,
            };
            let rst = memory_ref.write_buffer(iovec.buf, &to_write);
            if rst != ErrNo::Success {
                return rst;
            }
            size_read += to_write.len() as u32;
        }
        memory_ref.write_buffer(address, &u32::to_le_bytes(size_read))
    }

    #[inline]
    pub(crate) fn fd_readdir(
        &mut self,
        fd: &Fd,
        cookie: &DirCookie,
    ) -> ErrNo {
        let mut fs = lock_vfs!(self);
        match fs.fd_readdir(fd, cookie) {
            // TODO fill
            Ok(o) => ErrNo::Success,
            Err(e) => e,
        }
    }

    #[inline]
    pub(crate) fn fd_renumber(&mut self, old_fd: &Fd, new_fd: Fd) -> ErrNo {
        let mut fs = lock_vfs!(self);
        fs.fd_renumber(old_fd, new_fd)
    }

    #[inline]
    pub(crate) fn fd_seek(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32,
        offset: i64,
        whence: u8,
        address: u32,
    ) -> ErrNo {
        let whence = match Whence::try_from(whence) {
            Ok(o) => o,
            Err(e) => return ErrNo::Inval,
        };
        let mut fs = lock_vfs!(self);
        let new_offset = match fs.fd_seek(&fd.into(), offset, whence) {
            Ok(o) => o,
            Err(e) => return e,
        };
        println!("new_offset {:?} to fd {:?}", new_offset, fd);
        memory_ref.write_buffer(address, &u64::to_le_bytes(new_offset))
    }

    #[inline]
    pub(crate) fn fd_tell(&self, fd: &Fd) -> ErrNo {
        let mut fs = lock_vfs!(self);
        match fs.fd_tell(fd) {
            // TODO fill
            Ok(o) => ErrNo::Success,
            Err(e) => e,
        }
    }

    #[inline]
    pub(crate) fn fd_write(&mut self, memory_ref: &mut impl MemoryHandler, fd: u32, iovec_base: u32, iovec_count: u32, address: u32) -> ErrNo {
        let iovecs = match memory_ref.unpack_iovec_array(iovec_base, iovec_count) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let bufs = match memory_ref.read_iovec_scattered(&iovecs) {
            Ok(o) => o,
            Err(e) => return e,
        };

        let mut size_written = 0;
        for buf in bufs.iter() {
            println!("write {:?} to fd {:?}", buf, fd);
            let mut fs = lock_vfs!(self);
            size_written += match fs.fd_write_base(&fd.into(), buf.clone()) {
                Ok(o) => o,
                Err(e) => return e,
            };
        }
        memory_ref.write_buffer(address, &u32::to_le_bytes(size_written))
    }

    #[inline]
    pub(crate) fn path_create_directory(&mut self, fd: &Fd, path: String) -> ErrNo {
        let mut fs = lock_vfs!(self);
        fs.path_create_directory(fd, path)
    }

    #[inline]
    pub(crate) fn path_filestat_get(
        &mut self,
        fd: &Fd,
        flags: &LookupFlags,
        path: &String,
    ) -> ErrNo {
        let mut fs = lock_vfs!(self);
        match fs.path_filestat_get(fd, flags, path) {
            // TODO fill
            Ok(o) => ErrNo::Success,
            Err(e) => e,
        }
    }

    #[inline]
    pub(crate) fn path_open(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        fd: u32, 
        dir_flags: u32,
        path_address: u32,
        path_length: u32,
        oflags : u32,
        fs_rights_base: u64,
        fs_rights_inheriting: u64,
        fd_flags: u32,
        address: u32,
    ) -> ErrNo {
        let fd = Fd(fd);
        let path = match memory_ref.read_cstring(path_address, path_length) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let dir_flags = match LookupFlags::from_bits(dir_flags) {
            Some(o) => o,
            None => return ErrNo::Inval,
        };
        let oflags = match OpenFlags::from_bits(oflags as u16) {
            Some(o) => o,
            None => return ErrNo::Inval,
        };
        let fs_rights_base = match Rights::from_bits(fs_rights_base) {
            Some(o) => o,
            None => return ErrNo::Inval
        };
        let fs_rights_inheriting = match Rights::from_bits(fs_rights_inheriting) {
            Some(o) => o,
            None => return ErrNo::Inval,
        };
        let fd_flags = match FdFlags::from_bits(fd_flags as u16) {
            Some(o) => o,
            None => return ErrNo::Inval,
        };
        let mut fs = lock_vfs!(self);

        match fs.path_open(
            &self.principal,
            &fd,
            dir_flags,
            &path,
            oflags,
            fs_rights_base,
            fs_rights_inheriting,
            fd_flags,
        ) {
            Ok(result) => memory_ref.write_buffer(address, &u32::to_le_bytes(result.into())),
            Err(err) => err,
        }
    }

    #[inline]
    pub(crate) fn path_remove_directory(&mut self, fd: &Fd, path: &String) -> ErrNo {
        let mut fs = lock_vfs!(self);
        fs.path_remove_directory(fd, path)
    }

    #[inline]
    pub(crate) fn path_rename(
        &mut self,
        old_fd: &Fd,
        old_path: &String,
        new_fd: &Fd,
        new_path: String,
    ) -> ErrNo {
        let mut fs = lock_vfs!(self);
        fs.path_rename(old_fd, old_path, new_fd, new_path)
    }

    #[inline]
    pub(crate) fn random_get(
        &mut self,
        memory_ref: &mut impl MemoryHandler,
        buf_ptr: u32,
        length: u32,
    ) -> ErrNo {
        let mut fs = lock_vfs!(self);
        match fs.random_get(length) {
            Ok(result) => memory_ref.write_buffer(buf_ptr, &result),
            Err(err) => err,
        }
    }

    /// An internal function for the execution engine to directly read the file.
    #[inline]
    pub(crate) fn read_file_by_filename(&mut self, file_name : &str) -> Result<Vec<u8>,ErrNo> {
        let mut fs = self.filesystem.lock().map_err(|_|ErrNo::Busy)?;
        fs.read_file_by_filename(&Principal::InternalSuperUser, file_name)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Fatal host errors/runtime panics.
////////////////////////////////////////////////////////////////////////////////

/// A fatal, runtime error that terminates the Veracruz host immediately.  This
/// is akin to a "kernel panic" for Veracruz: these errors are not passed to the
/// WASM program running on the platform, but are instead fundamental issues
/// that require immediate shutdown as they cannot be fixed.
///
/// *NOTE*: care should be taken when presenting these errors to users when in
/// release (e.g. not in debug) mode: they can give away a lot of information
/// about what is going on inside the enclave.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum FatalEngineError {
    /// The WASM module supplied by the program supplier was invalid and could
    /// not be parsed.
    #[error(display = "FatalEngineError: Invalid WASM program (e.g. failed to parse it).")]
    InvalidWASMModule,
    //TODO REMOVE THIS ???
    /// The Veracruz host was passed bad arguments by the WASM program running
    /// on the platform.  This should never happen if the WASM program uses
    /// `libveracruz` as the platform should ensure H-Calls are always
    /// well-formed.  Seeing this either indicates a bug in `libveracruz` or a
    /// programming error in the source that originated the WASM programming if
    /// `libveracruz` was not used.
    #[error(
        display = "FatalEngineError: Bad arguments passed to host function '{:?}'.",
        function_name
    )]
    BadArgumentsToHostFunction {
        /// The name of the host function that was being invoked.
        function_name: WASIAPIName,
    },
    //TODO CHANGE TYPE
    /// The WASM program tried to invoke an unknown H-call on the Veracruz host.
    #[error(display = "FatalEngineError: Unknown H-call invoked: '{}'.", index)]
    UnknownHostFunction {
        /// The host call index of the unknown function that was invoked.
        index: usize,
    },
    /// No linear memory was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalEngineError: No WASM memory registered.")]
    NoMemoryRegistered,
    /// No program module was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalEngineError: No WASM program module registered.")]
    NoProgramModuleRegistered,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "FatalEngineError: Failed to find the entry point in the WASM program.")]
    NoProgramEntryPoint,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "FatalEngineError: Execution engine is not ready.")]
    EngineIsNotReady,
    /// Wrapper for direct error message.
    #[error(display = "FatalEngineError: WASM program returns code other than wasi ErrNo.")]
    ReturnedCodeError,
    /// A lock could not be obtained for some reason.
    #[error(display = "ProvisioningError: Failed to obtain lock {:?}.", _0)]
    FailedToObtainLock(String),
    /// Wrapper for WASI Trap.
    #[error(display = "FatalEngineError: WASMIError: Trap: {:?}.", _0)]
    WASMITrapError(#[source(error)] wasmi::Trap),
    /// Wrapper for WASI Error other than Trap.
    #[error(display = "FatalEngineError: WASMIError {:?}.", _0)]
    WASMIError(#[source(error)] wasmi::Error),
    //TODO CHANGE should be general
    #[error(display = "FatalEngineError: Wasi-ErrNo {:?}.", _0)]
    WASIError(#[source(error)] wasi_types::ErrNo),
    /// anyhow Error Wrapper.
    #[error(display = "FatalEngineError: anyhow Error {:?}.", _0)]
    AnyhowError(String),
    /// Wasmtime trap.
    #[error(display = "FatalEngineError: Wasmtime Trap Error {:?}.", _0)]
    WasmtimeTrapError(String),
    /// Wrapper for direct error message.
    #[error(display = "FatalEngineError: Error message {:?}.", _0)]
    DirectErrorMessage(String),
    /// Something unknown or unexpected went wrong, and there's no more detailed
    /// information.
    #[error(display = "FatalEngineError: Unknown error.")]
    Generic,
}

// Convertion from any error raised by any mutex of type <T> to FatalEngineError.
impl<T> From<std::sync::PoisonError<T>> for FatalEngineError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        FatalEngineError::FailedToObtainLock(format!("{:?}", error))
    }
}

impl From<String> for FatalEngineError {
    fn from(err: String) -> Self {
        FatalEngineError::DirectErrorMessage(err)
    }
}

impl From<&str> for FatalEngineError {
    fn from(err: &str) -> Self {
        FatalEngineError::DirectErrorMessage(err.to_string())
    }
}

impl From<anyhow::Error> for FatalEngineError {
    fn from(error: anyhow::Error) -> Self {
        FatalEngineError::AnyhowError(format!("{:?}", error))
    }
}

#[cfg(any(feature = "std", feature = "nitro"))]
impl From<wasmtime::Trap> for FatalEngineError {
    fn from(error: wasmtime::Trap) -> Self {
        FatalEngineError::WasmtimeTrapError(format!("{:?}", error))
    }
}

impl FatalEngineError {
    /// Constructs a `FatalEngineError::DirectErrorMessage` out of anything that can
    /// be converted into a string.
    #[inline]
    pub fn direct_error_message<T>(message: T) -> Self
    where
        T: Into<String>,
    {
        FatalEngineError::DirectErrorMessage(message.into())
    }

    /// Constructs a `FatalEngineError::BadArgumentsToHostFunction` out of anything
    /// that can be converted into a string.
    pub fn bad_arguments_to_host_function(fname: WASIAPIName) -> Self
    {
        FatalEngineError::BadArgumentsToHostFunction {
            function_name: fname,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Implementation of the H-calls.
////////////////////////////////////////////////////////////////////////////////

/// Details the arguments expected by the module's entry point, if any is found.
pub(crate) enum EntrySignature {
    /// The expected entry point (e.g. "main") is not found in the WASM module
    /// or it was found and it did not have a recognisable type signature.
    NoEntryFound,
    /// The entry point does not expect any parameters.
    NoParameters,
    /// The entry point expects a dummy `argv` and an `argc` to be supplied.
    ArgvAndArgc,
}

////////////////////////////////////////////////////////////////////////////////
// The strategy trait.
////////////////////////////////////////////////////////////////////////////////

/// This is what an execution strategy exposes to clients outside of this
/// library.  This functionality is sufficient to implement both
/// `freestanding-execution-engine` and `runtime-manager` and if any functionality is
/// missing that these components require then it should be added to this trait
/// and implemented for all supported implementation strategies.
///
/// Note that a factory method, in the file `hcall/factory.rs` will return an
/// opaque instance of this trait depending on the
pub trait ExecutionEngine: Send {
    /// Invokes the entry point of the WASM program `file_name`.  Will fail if
    /// the WASM program fails at runtime.  On success, returns the succ/error code
    /// returned by the WASM program entry point as an `i32` value.
    fn invoke_entry_point(&mut self, file_name: &str) -> Result<ErrNo, FatalEngineError>;
}
