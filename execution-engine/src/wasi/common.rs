//! Common code for any implementation of WASI:
//! - An interface for handling memory access.
//! - An interface for executing a program.
//! - A WASI Wrapper. It wraps the strictly type WASI-like API
//! in the virtual file system, and converts wasm number- and address-based
//! parameters to properly typed parameters and rust-style error handling to
//! c-style returning code.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(non_camel_case_types, clippy::too_many_arguments)]

use crate::{
    fs::{FileSystem, FileSystemResult},
    Options,
};

use byteorder::{LittleEndian, ReadBytesExt};
use err_derive::Error;
use platform_services::{getclockres, getclocktime, getrandom, result};
use serde::{Deserialize, Serialize};
use std::{
    convert::AsMut, convert::AsRef, convert::TryFrom, io::Cursor, mem::size_of,
    slice, slice::from_raw_parts, slice::from_raw_parts_mut,
    string::String, vec::Vec,
};
use wasi_types::{
    Advice, ClockId, DirEnt, ErrNo, Event, EventFdState, EventRwFlags, EventType, Fd, FdFlags,
    IoVec, LookupFlags, OpenFlags, RiFlags, Rights, RoFlags, SdFlags, SetTimeFlags, SiFlags,
    Signal, Subscription, SubscriptionClock, SubscriptionFdReadwrite, SubscriptionUnion, Timestamp,
    Whence,
};

////////////////////////////////////////////////////////////////////////////////
// Common constants.
////////////////////////////////////////////////////////////////////////////////

/// List of WASI API.
#[derive(Debug, PartialEq, Clone, FromPrimitive, ToPrimitive, Serialize, Deserialize, Copy)]
pub enum WasiAPIName {
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

impl TryFrom<&str> for WasiAPIName {
    type Error = ();
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let rst = match s {
            "args_get" => WasiAPIName::ARGS_GET,
            "args_sizes_get" => WasiAPIName::ARGS_SIZES_GET,
            "environ_get" => WasiAPIName::ENVIRON_GET,
            "environ_sizes_get" => WasiAPIName::ENVIRON_SIZES_GET,
            "clock_res_get" => WasiAPIName::CLOCK_RES_GET,
            "clock_time_get" => WasiAPIName::CLOCK_TIME_GET,
            "fd_advise" => WasiAPIName::FD_ADVISE,
            "fd_allocate" => WasiAPIName::FD_ALLOCATE,
            "fd_close" => WasiAPIName::FD_CLOSE,
            "fd_datasync" => WasiAPIName::FD_DATASYNC,
            "fd_fdstat_get" => WasiAPIName::FD_FDSTAT_GET,
            "fd_fdstat_set_flags" => WasiAPIName::FD_FDSTAT_SET_FLAGS,
            "fd_fdstat_set_rights" => WasiAPIName::FD_FDSTAT_SET_RIGHTS,
            "fd_filestat_get" => WasiAPIName::FD_FILESTAT_GET,
            "fd_filestat_set_size" => WasiAPIName::FD_FILESTAT_SET_SIZE,
            "fd_filestat_set_times" => WasiAPIName::FD_FILESTAT_SET_TIMES,
            "fd_pread" => WasiAPIName::FD_PREAD,
            "fd_prestat_get" => WasiAPIName::FD_PRESTAT_GET,
            "fd_prestat_dir_name" => WasiAPIName::FD_PRESTAT_DIR_NAME,
            "fd_pwrite" => WasiAPIName::FD_PWRITE,
            "fd_read" => WasiAPIName::FD_READ,
            "fd_readdir" => WasiAPIName::FD_READDIR,
            "fd_renumber" => WasiAPIName::FD_RENUMBER,
            "fd_seek" => WasiAPIName::FD_SEEK,
            "fd_sync" => WasiAPIName::FD_SYNC,
            "fd_tell" => WasiAPIName::FD_TELL,
            "fd_write" => WasiAPIName::FD_WRITE,
            "path_create_directory" => WasiAPIName::PATH_CREATE_DIRECTORY,
            "path_filestat_get" => WasiAPIName::PATH_FILESTAT_GET,
            "path_filestat_set_times" => WasiAPIName::PATH_FILESTAT_SET_TIMES,
            "path_link" => WasiAPIName::PATH_LINK,
            "path_open" => WasiAPIName::PATH_OPEN,
            "path_readlink" => WasiAPIName::PATH_READLINK,
            "path_remove_directory" => WasiAPIName::PATH_REMOVE_DIRECTORY,
            "path_rename" => WasiAPIName::PATH_RENAME,
            "path_symlink" => WasiAPIName::PATH_SYMLINK,
            "path_unlink_file" => WasiAPIName::PATH_UNLINK_FILE,
            "poll_oneoff" => WasiAPIName::POLL_ONEOFF,
            "proc_exit" => WasiAPIName::PROC_EXIT,
            "proc_raise" => WasiAPIName::PROC_RAISE,
            "sched_yield" => WasiAPIName::SCHED_YIELD,
            "random_get" => WasiAPIName::RANDOM_GET,
            "sock_recv" => WasiAPIName::SOCK_RECV,
            "sock_send" => WasiAPIName::SOCK_SEND,
            "sock_shutdown" => WasiAPIName::SOCK_SHUTDOWN,
            _otherwise => return Err(()),
        };
        Ok(rst)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Miscellanea that doesn't fit elsewhere.
////////////////////////////////////////////////////////////////////////////////

/// Unpack a sequence of `bytes` and return a `T`.
pub trait Unpack: Sized {
    const SIZE: u32;
    fn unpack(bytes: &[u8]) -> FileSystemResult<Self>;
}

impl Unpack for IoVec {
    const SIZE: u32 = size_of::<Self>() as u32;

    fn unpack(bytes: &[u8]) -> FileSystemResult<Self> {
        if bytes.len() != size_of::<IoVec>() {
            return Err(ErrNo::Inval);
        }
        let mut rdr = Cursor::new(bytes);
        let buf = rdr.read_u32::<LittleEndian>()?;
        let len = rdr.read_u32::<LittleEndian>()?;
        Ok(IoVec { buf, len })
    }
}

impl Unpack for Subscription {
    const SIZE: u32 = size_of::<Self>() as u32;

    fn unpack(bytes: &[u8]) -> FileSystemResult<Self> {
        if bytes.len() != size_of::<Subscription>() {
            return Err(ErrNo::Inval);
        }
        let mut rdr = Cursor::new(bytes);
        let userdata = rdr.read_u64::<LittleEndian>()?;
        // build SubscriptionUnion
        let tag = rdr.read_u64::<LittleEndian>()?;
        let u = match tag {
            // build clock
            0 => {
                let clock_id = rdr.read_u64::<LittleEndian>()?;
                let clock_id = u32::try_from(clock_id).map_err(|_| ErrNo::Inval)?;
                let clock_id = ClockId::try_from(clock_id).map_err(|_| ErrNo::Inval)?;
                let timeout = rdr.read_u64::<LittleEndian>()?.into();
                let precision = rdr.read_u64::<LittleEndian>()?.into();
                // NOTE: not sure if flags is read correctly as it is u16
                let flags = rdr.read_u64::<LittleEndian>()?;
                let flags = u16::try_from(flags).map_err(|_| ErrNo::Inval)?;
                let clock = SubscriptionClock {
                    clock_id,
                    timeout,
                    precision,
                    flags,
                };
                SubscriptionUnion::Clock(clock)
            }
            // FdRead or FdWrite
            1 | 2 => {
                let fd = rdr.read_u64::<LittleEndian>()?;
                let fd = u32::try_from(fd).map_err(|_| ErrNo::Inval)?.into();
                // Read the unused bytes
                rdr.read_u64::<LittleEndian>()?;
                rdr.read_u64::<LittleEndian>()?;
                rdr.read_u64::<LittleEndian>()?;
                let fd_rw = SubscriptionFdReadwrite { fd };
                if tag == 1 {
                    SubscriptionUnion::FdRead(fd_rw)
                } else {
                    SubscriptionUnion::FdWrite(fd_rw)
                }
            }
            _otherwise => return Err(ErrNo::Inval),
        };
        Ok(Subscription { userdata, u })
    }
}

impl Unpack for Event {
    const SIZE: u32 = size_of::<Self>() as u32;

    fn unpack(bytes: &[u8]) -> FileSystemResult<Self> {
        if bytes.len() != size_of::<Event>() {
            return Err(ErrNo::Inval);
        }
        let mut rdr = Cursor::new(bytes);
        let user_data = rdr.read_u64::<LittleEndian>()?;
        let error = rdr.read_u16::<LittleEndian>()?;
        let error = ErrNo::try_from(error).map_err(|_| ErrNo::Inval)?;
        // NOTE: not sure if ty (type) is read correctly as it is u16
        let ty = rdr.read_u48::<LittleEndian>()?;
        let ty = u8::try_from(ty).map_err(|_| ErrNo::Inval)?;
        let ty = EventType::try_from(ty).map_err(|_| ErrNo::Inval)?;
        let fd_state = if ty == EventType::FdRead || ty == EventType::FdWrite {
            let file_size = rdr.read_u64::<LittleEndian>()?;
            // NOTE: not sure if flag is read correctly as it is u64
            let flags = rdr.read_u64::<LittleEndian>()?;
            let flags = u16::try_from(flags).map_err(|_| ErrNo::Inval)?;
            let flags = EventRwFlags::try_from(flags).map_err(|_| ErrNo::Inval)?;
            Some(EventFdState { file_size, flags })
        } else {
            None
        };
        Ok(Event {
            user_data,
            error,
            ty,
            fd_state,
        })
    }
}


/// A type wrapping an array of IoVecs, this indirection is needed
/// to hold the MemoryHandler::Slice type which needs to be stored
/// somewhere
struct IoVecSlices<'a, R> {
    _ref: R,
    slices: Vec<&'a [u8]>,
}

impl<'a, R> AsRef<[&'a [u8]]> for IoVecSlices<'a, R> {
    fn as_ref(&self) -> &[&'a [u8]] {
        &self.slices
    }
}

/// A type wrapping an array of IoVecs, this indirection is needed
/// to hold the MemoryHandler::Slice type which needs to be stored
/// somewhere
struct IoVecSlicesMut<'a, R> {
    _ref: R,
    slices: Vec<&'a mut [u8]>,
}

impl<'a, R> AsMut<[&'a mut [u8]]> for IoVecSlicesMut<'a, R> {
    fn as_mut(&mut self) -> &mut [&'a mut [u8]] {
        &mut self.slices
    }
}


/// The memory handler for interacting with the wasm memory space.
/// An execution engine must implement `write_buffer` and `read_buffer`
/// before using the WasiWrapper, because the WASI implementation requires
/// an extra memory handler as the first parameter.
///
/// NOTE: we purposely choose u32 here as the execution engine is likely received u32 as
/// parameters
pub trait MemoryHandler<'a>  {
    type Slice: AsRef<[u8]>;
    type SliceMut: AsMut<[u8]>;

    fn get_slice(&'a self, address: u32, length: u32) -> FileSystemResult<Self::Slice>;

    fn get_slice_mut(&'a mut self, address: u32, length: u32) -> FileSystemResult<Self::SliceMut>;

    fn get_size(&'a self) -> FileSystemResult<u32>;

    /// Write the `buffer` to `address`.
    fn write_buffer(&'a mut self, address: u32, buffer: &[u8]) -> FileSystemResult<()> {
        self.get_slice_mut(address, u32::try_from(buffer.len()).unwrap())?
            .as_mut()
            .copy_from_slice(buffer);
        Ok(())
    }

    /// Read `length` bytes from `address`.
    fn read_buffer(&'a self, address: u32, buffer: &mut [u8]) -> FileSystemResult<()> {
        buffer.copy_from_slice(
            self.get_slice(address, u32::try_from(buffer.len()).unwrap())?
                .as_ref()
        );
        Ok(())
    }

    /// Reads a string at `address` of `length` from the runtime state's memory,
    /// starting at base address `address`.  If it fails, return ErrNo.
    fn read_cstring(&'a self, address: u32, length: u32) -> FileSystemResult<String> {
        let mut bytes = vec![0u8; usize::try_from(length).unwrap()];
        self.read_buffer(address, &mut bytes)?;
        let rst = String::from_utf8(bytes).map_err(|_e| ErrNo::IlSeq)?;
        Ok(rst)
    }

//    /// Performs a scattered read from several locations, as specified by a list
//    /// of `IoVec` structures, `scatters`, from the runtime state's memory.
//    fn read_iovec_scattered(&self, scatters: &[IoVec]) -> FileSystemResult<Vec<Vec<u8>>> {
//        let mut rst = Vec::new();
//        for IoVec { buf, len } in scatters.iter() {
//            rst.push(self.read_buffer(*buf, *len)?)
//        }
//        Ok(rst)
//    }
//
//    /// Reads a list of `IoVec` structures from a byte buffer.  Fails if reading of
//    /// any `IoVec` fails, for any reason.
//    fn unpack_array<T: Unpack<T>>(&self, ptr: u32, count: u32) -> FileSystemResult<Vec<T>> {
//        let size = size_of::<T>();
//        let all_bytes = self.read_buffer(ptr, count * (size as u32))?;
//        let mut rst = Vec::new();
//
//        for bytes in all_bytes.chunks(size) {
//            rst.push(T::unpack(bytes)?)
//        }
//        Ok(rst)
//    }

    /// The default implementation for writing a u32 to `address`.
    fn write_u32(&'a mut self, address: u32, number: u32) -> FileSystemResult<()> {
        self.write_buffer(address, &u32::to_le_bytes(number))
    }

    /// The default implementation for reading a u32 from `address`.
    fn read_u32(&'a self, address: u32) -> FileSystemResult<u32> {
        let mut bytes = [0u8; 4];
        self.read_buffer(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// The default implementation for writing a u64 to `address`.
    fn write_u64(&'a mut self, address: u32, number: u64) -> FileSystemResult<()> {
        self.write_buffer(address, &u64::to_le_bytes(number))
    }

    /// The default implementation for reading a u32 from `address`.
    fn read_u64(&'a self, address: u32) -> FileSystemResult<u64> {
        let mut bytes = [0u8; 8];
        self.read_buffer(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// The default implementation for writing a struct to `address`.
    fn write_struct<T: Sized>(&'a mut self, address: u32, element: &T) -> FileSystemResult<()> {
        let bytes: &[u8] =
            unsafe { from_raw_parts((element as *const T) as *const u8, size_of::<T>()) };
        self.write_buffer(address, bytes)
    }

    /// The default implementation for read a struct from `address`.
    fn read_struct<T: Sized>(&'a self, address: u32, element: &mut T) -> FileSystemResult<()> {
        let bytes: &mut [u8] =
            unsafe { from_raw_parts_mut((element as *mut T) as *mut u8, size_of::<T>()) };
        self.read_buffer(address, bytes)
    }

    /// The default implementation for read an Unpack from `address`.
    fn unpack<T: Unpack>(&'a self, address: u32) -> FileSystemResult<T> {
        let bytes = self.get_slice(address, T::SIZE)?;
        T::unpack(bytes.as_ref())
    }

    /// Unpack an array of Unpacks
    fn unpack_array<T: Unpack>(
        &'a self,
        address: u32,
        count: u32
    ) -> FileSystemResult<Vec<T>> {
        (0..count)
            .map(|i| self.unpack(address + i*T::SIZE))
            .collect()
    }

    //type IoVecSlice: AsRef<[u8]> = IoVecSlice<Self::Slice>;

    /// Unpack an array of iovec references
    fn unpack_iovec(
        &'a self,
        address: u32,
        count: u32
    ) -> FileSystemResult<IoVecSlices<'a, Self::Slice>> {
        // Just get a reference to all of memory, it's easier to manipulate
        // it this way
        let memory = self.get_slice(0, self.get_size()?)?;
        let mut slices = vec![];
        for i in 0..count {
            let iovec = IoVec::unpack(
                &memory.as_ref()[
                    usize::try_from(address + i*IoVec::SIZE).unwrap()
                        .. usize::try_from(address + (i+1)*IoVec::SIZE).unwrap()
                ]
            )?;

            let slice = &memory.as_ref()[
                usize::try_from(iovec.buf).unwrap()
                    .. usize::try_from(iovec.buf+iovec.len).unwrap()
            ];
            let ptr = slice.as_ptr();
            let len = slice.len();
            slices.push(unsafe { slice::from_raw_parts(ptr, len) });
        }


//        let slices = (0..count)
//            .map(|i| -> FileSystemResult<&'a [u8]> {
//                let iovec = IoVec::unpack(
//                    &memory.as_ref()[
//                        usize::try_from(address + i*IoVec::SIZE).unwrap()
//                            .. usize::try_from(address + (i+1)*IoVec::SIZE).unwrap()
//                    ]
//                )?;
//
//                Ok(&memory.as_ref()[
//                    usize::try_from(iovec.buf).unwrap()
//                        .. usize::try_from(iovec.buf+iovec.len).unwrap()
//                ])
//            })
//            .collect::<FileSystemResult<Vec<_>>>()?;

        Ok(IoVecSlices{_ref: memory, slices})
    }

    /// Unpack an array of mutable iovec references
    fn unpack_iovec_mut(
        &'a mut self,
        address: u32,
        count: u32
    ) -> FileSystemResult<IoVecSlicesMut<'a, Self::SliceMut>> {
        // Just get a reference to all of memory, it's easier to manipulate
        // it this way
        let size = self.get_size()?;
        let mut memory = self.get_slice_mut(0, size)?;
        let slices = (0..count)
            .map(|i| -> FileSystemResult<&'a mut [u8]> {
                let iovec = IoVec::unpack(
                    &memory.as_mut()[
                        usize::try_from(address + i*IoVec::SIZE).unwrap()
                            .. usize::try_from(address + (i+1)*IoVec::SIZE).unwrap()
                    ]
                )?;

                // The _correct_ thing to do here is to
                // 1. allocate and read all iovecs first
                // 2. sort the iovecs by address
                // 3. check for overlapping ranges
                // 4. repeat slice::split_at to separate memory into sub-slices
                //    containing the slices specified by iovec
                //
                // Or we can just use a tiny be of unsafety here
                //
                let slice = &mut memory.as_mut()[
                    usize::try_from(iovec.buf).unwrap()
                        .. usize::try_from(iovec.buf+iovec.len).unwrap()
                ];
                let ptr = slice.as_mut_ptr();
                let len = slice.len();
                Ok(unsafe { slice::from_raw_parts_mut(ptr, len)})
            })
            .collect::<FileSystemResult<Vec<_>>>()?;

        Ok(IoVecSlicesMut{_ref: memory, slices})
    }

//    /// Unpack an array of Unpacks
//    ///
//    /// Note this requires a Box, this is due to restrictions on impl traits in
//    /// traits. Normally you would use an associated type and specify the type
//    /// fully, but because this involves a closure, the type is
//    /// _unspecifiable_. An alternative would be to move this to a standalone
//    /// function.
//    ///
//    fn iter_unpack<T: Unpack>(
//        &'a self,
//        address: u32,
//        count: u32
//    ) -> FileSystemResult<Box<dyn Iterator<Item=FileSystemResult<T>> + 'a>> {
//        Ok(Box::new(
//            (0..count).map(|i| {
//                self.read_unpack(address + i*T::SIZE)
//            })
//        ))
//    }
//
//    /// Unpack an array of IoVecs, getting MemoryRef's Slice types which can
//    /// be read from
//    ///
//    fn iter_iovec(
//        &'a self,
//        address: u32,
//        count: u32
//    ) -> FileSystemResult<Box<dyn Iterator<Item=FileSystemResult<Self::Slice>> + 'a>> {
//        // a bit of code from iter_unpack is duplicated here to avoid
//        // an additional alloc
//        Ok(Box::new(
//            (0..count).map(|i| {
//                let iovec = self.read_unpack::<IoVec>(address + i*IoVec::SIZE)?;
//                self.get_slice(iovec.buf, iovec.len)
//            })
//        ))
//    }
//
//    /// Unpack an array of IoVecs, getting MemoryRef's SliceMut types which can
//    /// be written to
//    ///
//    fn iter_iovec_mut(
//        &'a mut self,
//        address: u32,
//        count: u32
//    ) -> FileSystemResult<Box<dyn Iterator<Item=FileSystemResult<Self::SliceMut>> + 'a>> {
//        // a bit of code from iter_unpack is duplicated here to avoid
//        // an additional alloc
//        Ok(Box::new(
//            (0..count).map(|i| {
//                // this is required for some reason
//                let self_ = self;
//                let iovec = self_.read_unpack::<IoVec>(address + i*IoVec::SIZE)?;
//                self_.get_slice_mut(iovec.buf, iovec.len)
//            })
//        ))
//    }

//    type IoVecSlice: AsRef<[u8]> = IoVecSliceHandler;
//    type IoVecSliceMut: AsMut<[u8]> = IoVecSliceMutHandler;
//
//    fn unpack_iovec(
//        &'a self,
//        address,
//        count
//    ) -> FileSystemResult<Self::IoVecSlice> {
//        todo!()
//    }
//
//    fn unpack_iovec_mut(
//        &'a mut self,
//        address,
//        count
//    ) -> FileSystemResult<Self::IoVecSliceMut> {
//        todo!()
//    }

    /// Write the content to the buf_address and the starting address to buf_pointers.
    /// For example:
    /// buf_address:
    /// --------------------------------------------------------------------
    ///  content[0] content[1] ......
    /// --------------------------------------------------------------------
    ///    ^           ^
    ///   0x10        0x64
    /// buf_pointers: [0x10, 0x64, ...]
    ///
    fn write_string_list(
        &'a mut self,
        content: &[Vec<u8>],
        mut buf_address: u32,
        mut buf_pointers: u32,
    ) -> FileSystemResult<()> {
        for to_write in content {
            // Write to the buf
            self.write_buffer(buf_address, &to_write)?;
            // Write to the pointer array
            self.write_u32(buf_pointers, buf_address)?;
            // Modify the offset
            buf_address += to_write.len() as u32;
            buf_pointers += size_of::<u32>() as u32;
        }
        Ok(())
    }
}
////////////////////////////////////////////////////////////////////////////////
// The host runtime state.
////////////////////////////////////////////////////////////////////////////////

/// A wrapper on VFS for WASI, which provides common API used by wasm execution engine.
#[derive(Clone)]
pub struct WasiWrapper {
    /// The synthetic filesystem associated with this machine.
    /// Note: Veracruz runtime should hold the root FileSystem handler.
    ///       The FileSystem handler here should be a non-root handler spawned
    ///       fro the root one.
    ///       Both the Veracruz runtime and this WasiWrapper can update, i.e. mutate,
    ///       the file system internal state, if their local FileSystem handlers have
    ///       the appropriate capabilities.
    ///       ---------------------------
    ///           Runtime  |  WasiWrapper
    /// FileSystem(handler)| FileSystem(handler)
    ///               v    |   v
    ///       ---------------------------
    ///            |  ^        ^  |
    ///            |  Internal    |
    ///            ----------------
    filesystem: FileSystem,
    /// The environment variables that have been passed to this program from the
    /// global policy file.  These are stored as a key-value mapping from
    /// variable name to value.
    pub(crate) environment_variables: Vec<(String, String)>,
    /// The array of program arguments that have been passed to this program,
    /// again from the global policy file.
    pub(crate) program_arguments: Vec<String>,
    /// The exit code, if program calls proc_exit.
    exit_code: Option<u32>,
    /// Whether clock functions (`clock_getres()`, `clock_gettime()`) should be enabled.
    pub(crate) enable_clock: bool,
}

impl WasiWrapper {
    /// The name of the WASM program's entry point.
    pub(crate) const ENTRY_POINT_NAME: &'static str = "_start";
    /// The name of the WASM program's linear memory.
    pub(crate) const LINEAR_MEMORY_NAME: &'static str = "memory";
    /// The name of the containing module for all WASI imports.
    pub(crate) const WASI_SNAPSHOT_MODULE_NAME: &'static str = "wasi_snapshot_preview1";

    ////////////////////////////////////////////////////////////////////////////
    // Creating and modifying runtime states.
    ////////////////////////////////////////////////////////////////////////////

    /// Creates a new initial `WasiWrapper`. It will spawn a new filesystem handler for the
    /// `principal` from `filesystem`
    #[inline]
    pub fn new(filesystem: FileSystem, enable_clock: bool) -> FileSystemResult<Self> {
        Ok(Self {
            filesystem,
            environment_variables: Vec::new(),
            program_arguments: Vec::new(),
            exit_code: None,
            enable_clock,
        })
    }

    ///////////////////////////////////////////////////////
    //// Functions for the execution engine internal
    ///////////////////////////////////////////////////////

    /// Return the exit code from `proc_exit` call.
    #[inline]
    pub(crate) fn exit_code(&self) -> Option<u32> {
        self.exit_code
    }

    /// Return a timestamp value for use by "filestat" functions,
    /// which will be zero if the clock is not enabled.
    fn filestat_time(&self) -> Timestamp {
        let time0 = Timestamp::from_nanos(0);
        if !self.enable_clock {
            time0
        } else {
            match getclocktime(ClockId::RealTime as u8) {
                result::Result::Success(timespec) => Timestamp::from_nanos(timespec),
                _ => time0,
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // WASI implementation
    ////////////////////////////////////////////////////////////////////////////

    /// The implementation of the WASI `args_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn args_get<'a, T: MemoryHandler<'a>>(
        &self,
        memory_ref: &'a mut T,
        address_for_string_ptrs: u32,
        buf_address: u32,
    ) -> FileSystemResult<()> {
        let buffer = self
            .program_arguments
            .iter()
            .map(|arg| format!("{}\0", arg).into_bytes())
            .collect::<Vec<_>>();
        memory_ref.write_string_list(&buffer, buf_address, address_for_string_ptrs)
    }

    /// The implementation of the WASI `args_sizes_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn args_sizes_get<'a, T: MemoryHandler<'a>>(
        &self,
        memory_ref: &'a mut T,
        address_for_counts: u32,
        address_for_buffer_size: u32,
    ) -> FileSystemResult<()> {
        let environc = self.program_arguments.len() as u32;
        let environ_buf_size = self
            .program_arguments
            .iter()
            .fold(0, |acc, arg| acc + format!("{}\0", arg).as_bytes().len());

        memory_ref.write_u32(address_for_counts, environc)?;
        memory_ref.write_u32(address_for_buffer_size, environ_buf_size as u32)
    }

    /// The implementation of the WASI `environ_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn environ_get<'a, T: MemoryHandler<'a>>(
        &self,
        memory_ref: &'a mut T,
        address_for_string_ptrs: u32,
        buf_address: u32,
    ) -> FileSystemResult<()> {
        let buffer = self
            .environment_variables
            .iter()
            .map(|(key, value)| {
                let environ = format!("{}={}\0", key, value);
                environ.into_bytes()
            })
            .collect::<Vec<_>>();
        memory_ref.write_string_list(&buffer, buf_address, address_for_string_ptrs)
    }

    /// THe implementation of the WASI `environ_sizes_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn environ_sizes_get<'a, T: MemoryHandler<'a>>(
        &self,
        memory_ref: &'a mut T,
        address_for_counts: u32,
        address_for_buffer_size: u32,
    ) -> FileSystemResult<()> {
        let environc = self.environment_variables.len() as u32;
        let environ_buf_size = self
            .environment_variables
            .iter()
            .fold(0, |acc, (key, value)| {
                acc + format!("{}={}\0", key, value).as_bytes().len()
            });

        memory_ref.write_u32(address_for_counts, environc)?;
        memory_ref.write_u32(address_for_buffer_size, environ_buf_size as u32)
    }

    /// The implementation of the WASI `clock_res_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn clock_res_get<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        clock_id: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let result = if !self.enable_clock {
            Err(ErrNo::Access)
        } else {
            let clock_id = clock_id as u8;
            match getclockres(clock_id) {
                result::Result::Success(resolution) => Ok(Timestamp::from_nanos(resolution)),
                result::Result::Unavailable => Err(ErrNo::NoSys),
                _ => Err(ErrNo::Inval),
            }
        }?;
        memory_ref.write_u64(address, result.as_nanos())
    }

    /// The implementation of the WASI `clock_time_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn clock_time_get<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        clock_id: u32,
        _precision: u64,
        address: u32,
    ) -> FileSystemResult<()> {
        let result = if !self.enable_clock {
            Err(ErrNo::Access)
        } else {
            let clock_id = clock_id as u8;
            match getclocktime(clock_id) {
                result::Result::Success(timespec) => Ok(Timestamp::from_nanos(timespec)),
                result::Result::Unavailable => Err(ErrNo::NoSys),
                _ => Err(ErrNo::Inval),
            }
        }?;
        memory_ref.write_u64(address, result.as_nanos())
    }

    /// The implementation of the WASI `fd_advise` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_advise<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &mut T,
        fd: u32,
        offset: u64,
        len: u64,
        advice: u8,
    ) -> FileSystemResult<()> {
        let advice: Advice = Self::decode_wasi_arg(advice)?;

        self.filesystem.fd_advise(fd.into(), offset, len, advice)
    }

    /// The implementation of the WASI `fd_allocate` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_allocate<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &mut T,
        fd: u32,
        offset: u64,
        len: u64,
    ) -> FileSystemResult<()> {
        self.filesystem.fd_allocate(fd.into(), offset, len)
    }

    /// The implementation of the WASI `fd_close` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_close<'a, T: MemoryHandler<'a>>(
        &mut self,
        _memory_ref: &T,
        fd: u32,
    ) -> FileSystemResult<()> {
        self.filesystem.fd_close(fd.into())
    }

    /// The implementation of the WASI `fd_datasync` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_datasync<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &'a mut T,
        fd: u32,
    ) -> FileSystemResult<()> {
        self.filesystem.fd_datasync(fd.into())
    }

    /// The implementation of the WASI `fd_fdstat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_fdstat_get<'a, T: MemoryHandler<'a>>(
        &self,
        memory_ref: &'a mut T,
        fd: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let stat = self.filesystem.fd_fdstat_get(fd.into())?;
        memory_ref.write_struct(address, &stat)
    }

    /// The implementation of the WASI `fd_fdstat_set_flags` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_fdstat_set_flags<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &'a mut T,
        fd: u32,
        flags: u16,
    ) -> FileSystemResult<()> {
        let flags: FdFlags = Self::decode_wasi_arg(flags)?;

        self.filesystem.fd_fdstat_set_flags(fd.into(), flags)
    }

    /// The implementation of the WASI `fd_fdstat_set_rights` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_fdstat_set_rights<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &'a mut T,
        fd: u32,
        rights_base: u64,
        rights_inheriting: u64,
    ) -> FileSystemResult<()> {
        let rights_base: Rights = Self::decode_wasi_arg(rights_base)?;
        let rights_inheriting: Rights = Self::decode_wasi_arg(rights_inheriting)?;

        self.filesystem
            .fd_fdstat_set_rights(fd.into(), rights_base, rights_inheriting)
    }

    /// The implementation of the WASI `fd_filestat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_filestat_get<'a, T: MemoryHandler<'a>>(
        &self,
        memory_ref: &'a mut T,
        fd: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let stat = self.filesystem.fd_filestat_get(fd.into());
        memory_ref.write_struct(address, &stat)
    }

    /// The implementation of the WASI `fd_filestat_set_size` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_filestat_set_size<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &'a mut T,
        fd: u32,
        size: u64,
    ) -> FileSystemResult<()> {
        self.filesystem.fd_filestat_set_size(fd.into(), size)
    }

    /// The implementation of the WASI `fd_filestat_set_times` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_filestat_set_times<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &'a mut T,
        fd: u32,
        atime: u64,
        mtime: u64,
        fst_flag: u16,
    ) -> FileSystemResult<()> {
        let fst_flag: SetTimeFlags = Self::decode_wasi_arg(fst_flag)?;
        self.filesystem.fd_filestat_set_times(
            fd.into(),
            atime.into(),
            mtime.into(),
            fst_flag,
            self.filestat_time(),
        )
    }

    /// The implementation of the WASI `fd_pread` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_pread<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        mut offset: u64,
        address: u32,
    ) -> FileSystemResult<()> {
        let iovecs = memory_ref.unpack_iovec_mut(iovec_base, iovec_count)?;
        let size_read = self.filesystem.fd_pread(
            fd.into(),
            iovecs.as_mut(),
            offset
        )?;
        memory_ref.write_u32(address, size_read as u32)
//
//        let mut size_read = 0;
//        for iovec in memory_ref.unpack::<IoVec>(iovec_base, iovec_count)? {
//            let iovec = iovec?;
//            let read_len = self.filesystem
//                .fd_pread(
//                    fd.into(),
//                    memory_ref.get_slice_mut(iovec.buf, iovec.len)?.as_mut(),
//                    offset
//                )?;
//            offset += read_len as u64;
//            size_read += read_len;
//        }
//        memory_ref.write_u32(address, size_read as u32)
//
//
//        let iovecs = memory_ref.unpack_array::<IoVec>(iovec_base, iovec_count)?;
//
//        let mut size_read = 0;
//        for iovec in iovecs.iter() {
//            let to_write = self
//                .filesystem
//                .fd_pread(fd.into(), iovec.len as usize, offset)?;
//            offset = offset + (to_write.len() as u64);
//            memory_ref.write_buffer(iovec.buf, &to_write)?;
//            size_read += to_write.len() as u32;
//        }
//        memory_ref.write_u32(address, size_read)
    }

    /// The implementation of the WASI `fd_prestat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_prestat_get<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let fd = Fd(fd);
        let pre = self.filesystem.fd_prestat_get(fd)?;
        memory_ref.write_struct(address, &pre)
    }

    /// The implementation of the WASI `fd_prestat_dir_name` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_prestat_dir_name<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        address: u32,
        size: u32,
    ) -> FileSystemResult<()> {
        let size = size as usize;

        let result = self
            .filesystem
            .fd_prestat_dir_name(fd.into())?
            .into_os_string();
        if result.len() > size as usize {
            return Err(ErrNo::NameTooLong);
        }
        let result = result.into_string().map_err(|_| ErrNo::Inval)?;
        memory_ref.write_buffer(address, result.as_bytes())
    }

    /// The implementation of the WASI `fd_pwrite` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_pwrite<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        offset: u64,
        address: u32,
    ) -> FileSystemResult<()> {
        let iovecs = memory_ref.unpack_iovec(iovec_base, iovec_count)?;
        let size_written = self.filesystem.fd_pwrite(
            fd.into(),
            iovecs.as_ref(),
            offset
        )?;
        memory_ref.write_u32(address, size_written as u32)
    }

    /// The implementation of the WASI `fd_read` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_read<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let iovecs = memory_ref.unpack_iovec_mut(iovec_base, iovec_count)?;
        let size_read = self.filesystem.fd_read(
            fd.into(),
            iovecs.as_mut(),
        )?;
        memory_ref.write_u32(address, size_read as u32)
//        let iovecs = memory_ref.unpack_array::<IoVec>(iovec_base, iovec_count)?;
//
//        let mut size_read = 0;
//        for iovec in iovecs.iter() {
//            let to_write = self.filesystem.fd_read(fd.into(), iovec.len as usize)?;
//            memory_ref.write_buffer(iovec.buf, &to_write)?;
//            size_read += to_write.len() as u32;
//        }
//        memory_ref.write_u32(address, size_read)
    }

    /// The implementation of the WASI `fd_readdir` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_readdir<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        mut buf_ptr: u32,
        buf_len: u32,
        cookie: u64,
        result_ptr: u32,
    ) -> FileSystemResult<()> {
        let dir_entries = self.filesystem.fd_readdir(fd.into(), cookie.into())?;

        let mut written = 0;
        for (dir, path) in dir_entries {
            //NOTE: `buf_len` is the number of bytes dir entries can store.
            //      If there is not enough space, stop writing and leave the rest of the buffer
            //      untouched.
            written += size_of::<DirEnt>() as u32;
            if written > buf_len {
                written = buf_len;
                break;
            }
            memory_ref.write_struct(buf_ptr, &dir)?;
            buf_ptr += size_of::<DirEnt>() as u32;

            written += path.len() as u32;
            if written > buf_len {
                written = buf_len;
                break;
            }
            memory_ref.write_buffer(buf_ptr, &path)?;
            buf_ptr += path.len() as u32;
        }
        memory_ref.write_u32(result_ptr, written as u32)
    }

    /// The implementation of the WASI `fd_renumber` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_renumber<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &'a mut T,
        old_fd: u32,
        new_fd: u32,
    ) -> FileSystemResult<()> {
        self.filesystem.fd_renumber(old_fd.into(), new_fd.into())
    }

    /// The implementation of the WASI `fd_seek` function.
    pub(crate) fn fd_seek<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        offset: i64,
        whence: u8,
        address: u32,
    ) -> FileSystemResult<()> {
        let whence: Whence = Self::decode_wasi_arg(whence)?;

        let new_offset = self.filesystem.fd_seek(fd.into(), offset, whence)?;
        memory_ref.write_u64(address, new_offset)
    }

    /// The implementation of the WASI `fd_sync` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_sync<'a, T: MemoryHandler<'a>>(&mut self, _: &'a mut T, fd: u32) -> FileSystemResult<()> {
        self.filesystem.fd_sync(fd.into())
    }

    /// The implementation of the WASI `fd_tell` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_tell<'a, T: MemoryHandler<'a>>(
        &self,
        memory_ref: &'a mut T,
        fd: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let offset = self.filesystem.fd_tell(fd.into())?;
        memory_ref.write_u64(address, offset)
    }

    /// The implementation of the WASI `fd_write` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn fd_write<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let iovecs = memory_ref.unpack_iovec(iovec_base, iovec_count)?;
        let size_written = self.filesystem.fd_write(
            fd.into(),
            iovecs.as_ref(),
        )?;
        memory_ref.write_u32(address, size_written as u32)
//        let iovecs = memory_ref.unpack_array::<IoVec>(iovec_base, iovec_count)?;
//        let bufs = memory_ref.read_iovec_scattered(&iovecs)?;
//
//        let mut size_written = 0;
//        for buf in bufs.iter() {
//            size_written += self.filesystem.fd_write(fd.into(), buf)?;
//        }
//        memory_ref.write_u32(address, size_written)
    }

    /// The implementation of the WASI `path_create_directory` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_create_directory<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        path_address: u32,
        path_length: u32,
    ) -> FileSystemResult<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;

        self.filesystem.path_create_directory(fd.into(), path)
    }

    /// The implementation of the WASI `path_filestat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_filestat_get<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        flags: u32,
        path_address: u32,
        path_length: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;
        let flags: LookupFlags = Self::decode_wasi_arg(flags)?;

        let stat = self.filesystem.path_filestat_get(fd.into(), flags, path)?;
        memory_ref.write_struct(address, &stat)
    }

    /// The implementation of the WASI `path_filestat_set_times` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_filestat_set_times<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        flags: u32,
        path_address: u32,
        path_length: u32,
        atime: u64,
        mtime: u64,
        fst_flag: u16,
    ) -> FileSystemResult<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;
        let flags: LookupFlags = Self::decode_wasi_arg(flags)?;
        let fst_flag: SetTimeFlags = Self::decode_wasi_arg(fst_flag)?;

        self.filesystem.path_filestat_set_times(
            fd.into(),
            flags,
            path,
            atime.into(),
            mtime.into(),
            fst_flag,
            self.filestat_time(),
        )
    }

    /// The implementation of the WASI `path_link` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_link<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        old_fd: u32,
        old_flags: u32,
        old_address: u32,
        old_path_len: u32,
        new_fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> FileSystemResult<()> {
        let old_flags: LookupFlags = Self::decode_wasi_arg(old_flags)?;
        let old_path = memory_ref.read_cstring(old_address, old_path_len)?;
        let new_path = memory_ref.read_cstring(new_address, new_path_len)?;

        self.filesystem
            .path_link(old_fd.into(), old_flags, old_path, new_fd.into(), new_path)
    }

    /// The implementation of the WASI `path_open` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_open<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        dir_flags: u32,
        path_address: u32,
        path_length: u32,
        oflags: u16,
        fs_rights_base: u64,
        fs_rights_inheriting: u64,
        fd_flags: u16,
        address: u32,
    ) -> FileSystemResult<()> {
        let fd = Fd(fd);
        let path = memory_ref.read_cstring(path_address, path_length)?;
        let dir_flags: LookupFlags = Self::decode_wasi_arg(dir_flags)?;
        let oflags: OpenFlags = Self::decode_wasi_arg(oflags)?;
        let fs_rights_base: Rights = Self::decode_wasi_arg(fs_rights_base)?;
        let fs_rights_inheriting: Rights = Self::decode_wasi_arg(fs_rights_inheriting)?;
        let fd_flags: FdFlags = Self::decode_wasi_arg(fd_flags)?;

        let new_fd = self.filesystem.path_open(
            fd,
            dir_flags,
            &path,
            oflags,
            fs_rights_base,
            fs_rights_inheriting,
            fd_flags,
        )?;
        memory_ref.write_u32(address, new_fd.into())
    }

    /// The implementation of the WASI `path_readlink` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_readlink<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        path_address: u32,
        path_length: u32,
        buf: u32,
        buf_len: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;

        let mut rst = self.filesystem.path_readlink(fd.into(), path)?;
        let buf_len = buf_len as usize;
        let to_write = if buf_len < rst.len() {
            buf_len
        } else {
            rst.len()
        };
        //NOTE: it should at most shrink the size of rst.
        rst.resize(to_write, 0);
        memory_ref.write_buffer(buf, &rst)?;
        memory_ref.write_u32(address, to_write as u32)
    }

    /// The implementation of the WASI `path_remove_directory` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_remove_directory<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        path_address: u32,
        path_length: u32,
    ) -> FileSystemResult<()> {
        let path = memory_ref.read_cstring(path_address, path_length)?;

        self.filesystem.path_remove_directory(fd.into(), path)
    }

    /// The implementation of the WASI `path_rename` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_rename<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        old_fd: u32,
        old_address: u32,
        old_path_len: u32,
        new_fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> FileSystemResult<()> {
        let old_path = memory_ref.read_cstring(old_address, old_path_len)?;
        let new_path = memory_ref.read_cstring(new_address, new_path_len)?;

        self.filesystem
            .path_rename(old_fd.into(), old_path, new_fd.into(), new_path)
    }

    /// The implementation of the WASI `path_symlink` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_symlink<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        old_address: u32,
        old_path_len: u32,
        fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> FileSystemResult<()> {
        let old_path = memory_ref.read_cstring(old_address, old_path_len)?;
        let new_path = memory_ref.read_cstring(new_address, new_path_len)?;

        self.filesystem.path_symlink(old_path, fd.into(), new_path)
    }

    /// The implementation of the WASI `path_unlink_file` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn path_unlink_file<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        fd: u32,
        path_address: u32,
        path_len: u32,
    ) -> FileSystemResult<()> {
        let path = memory_ref.read_cstring(path_address, path_len)?;

        self.filesystem.path_unlink_file(fd.into(), path)
    }

    /// The implementation of the WASI `poll_oneoff` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn poll_oneoff<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        subscriptions: u32,
        events: u32,
        size: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let subscriptions = memory_ref.unpack_array::<Subscription>(subscriptions, size)?;
        let events = memory_ref.unpack_array::<Event>(events, size)?;

        let rst = self.filesystem.poll_oneoff(subscriptions, events)?;
        memory_ref.write_u32(address, rst)
    }

    /// The implementation of the WASI `proc_exit` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn proc_exit<'a, T: MemoryHandler<'a>>(&mut self, _: &'a mut T, exit_code: u32) {
        self.exit_code = Some(exit_code);
    }

    /// The implementation of the WASI `proc_raise` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn proc_raise<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &'a mut T,
        signal: u8,
    ) -> FileSystemResult<()> {
        let _signal: Signal = Self::decode_wasi_arg(signal)?;
        Err(ErrNo::NoSys)
    }

    /// The implementation of the WASI `sched_yield` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn sched_yield<'a, T: MemoryHandler<'a>>(&mut self, _: &'a mut T) -> FileSystemResult<()> {
        Err(ErrNo::NoSys)
    }

    pub(crate) fn random_get<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        buf_ptr: u32,
        length: u32,
    ) -> FileSystemResult<()> {
        let mut bytes = vec![0; length as usize];
        if getrandom(&mut bytes).is_success() {
            memory_ref.write_buffer(buf_ptr, &bytes)
        } else {
            Err(ErrNo::NoSys)
        }
    }

    /// The implementation of the WASI `sock_recv` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn sock_recv<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        socket: u32,
        ri_address: u32,
        ri_len: u32,
        ri_flag: u16,
        ro_data_len: u32,
        ro_flag: u32,
    ) -> FileSystemResult<()> {
        let iovecs = memory_ref.unpack_iovec_mut(ri_address, ri_len)?;
        let ri_flags: RiFlags = Self::decode_wasi_arg(ri_flag)?;
        let (size_read, ro_flags) = self.filesystem.sock_recv(
            socket.into(),
            iovecs.as_mut(),
            ri_flags
        )?;
        let ro_flags = RoFlags::empty() | ro_flags;
        memory_ref.write_u32(ro_data_len, size_read as u32)?;
        memory_ref.write_buffer(ro_flag, &u16::to_le_bytes(ro_flags.bits()))

//        let iovecs = memory_ref.unpack_array::<IoVec>(ri_address, ri_len)?;
//        let ri_flag: RiFlags = Self::decode_wasi_arg(ri_flag)?;
//
//        let mut size_read = 0;
//        let mut ro_rst = RoFlags::empty();
//        for iovec in iovecs.iter() {
//            let (to_write, next_ro_rst) =
//                self.filesystem
//                    .sock_recv(socket.into(), iovec.len as usize, ri_flag)?;
//            memory_ref.write_buffer(iovec.buf, &to_write)?;
//            size_read += to_write.len() as u32;
//            ro_rst = ro_rst | next_ro_rst;
//        }
//        memory_ref.write_u32(ro_data_len, size_read)?;
//        memory_ref.write_buffer(ro_flag, &u16::to_le_bytes(ro_rst.bits()))
    }

    /// The implementation of the WASI `sock_send` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn sock_send<'a, T: MemoryHandler<'a>>(
        &mut self,
        memory_ref: &'a mut T,
        socket: u32,
        si_address: u32,
        si_len: u32,
        si_flag: u16,
        address: u32,
    ) -> FileSystemResult<()> {
        let iovecs = memory_ref.unpack_iovec(si_address, si_len)?;
        let si_flags: SiFlags = Self::decode_wasi_arg(si_flag)?;
        let size_written = self.filesystem.sock_send(
            socket.into(),
            iovecs.as_ref(),
            si_flags
        )?;
        memory_ref.write_u32(address, size_written as u32)
//        let iovecs = memory_ref.unpack_array::<IoVec>(si_address, si_len)?;
//        let bufs = memory_ref.read_iovec_scattered(&iovecs)?;
//        let si_flag: SiFlags = Self::decode_wasi_arg(si_flag)?;
//
//        let mut size_written = 0;
//        for buf in bufs.iter() {
//            size_written += self.filesystem.sock_send(socket.into(), buf, si_flag)?;
//        }
//        memory_ref.write_u32(address, size_written)
    }

    /// The implementation of the WASI `sock_recv` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.                  
    pub(crate) fn sock_shutdown<'a, T: MemoryHandler<'a>>(
        &mut self,
        _: &'a mut T,
        socket: u32,
        sd_flag: u8,
    ) -> FileSystemResult<()> {
        let sd_flag: SdFlags = Self::decode_wasi_arg(sd_flag)?;

        self.filesystem.sock_shutdown(socket.into(), sd_flag)
    }

    ///////////////////////////////////////
    // Internal methods
    ///////////////////////////////////////
    /// Converts `arg` of type `R` to type `T`,
    /// or returns from the function with the `Inval` error code.
    #[inline]
    fn decode_wasi_arg<T: TryFrom<R>, R>(arg: R) -> FileSystemResult<T> {
        T::try_from(arg).map_err(|_| ErrNo::Inval)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Fatal execution errors/runtime panics.
////////////////////////////////////////////////////////////////////////////////

/// A fatal, runtime error that terminates the Veracruz execution immediately.  This
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
    /// The Veracruz engine was passed bad arguments by the WASM program running
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
        function_name: WasiAPIName,
    },
    /// The WASM program tried to invoke an unknown H-call on the Veracruz engine.
    #[error(display = "FatalEngineError: Unknown Host call invoked: '{:?}'.", _0)]
    UnknownHostFunction(HostFunctionIndexOrName),
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
    /// A lock could not be obtained for some reason, wrappiing the failure information as String.
    #[error(display = "ProvisioningError: Failed to obtain lock {:?}.", _0)]
    FailedToObtainLock(String),
    /// Wrapper for WASI Trap.
    #[error(display = "FatalEngineError: WASMIError: Trap: {:?}.", _0)]
    WASMITrapError(#[source(error)] wasmi::Trap),
    /// Wrapper for WASI Error other than Trap.
    #[error(display = "FatalEngineError: WASMIError {:?}.", _0)]
    WASMIError(#[source(error)] wasmi::Error),
    #[error(display = "FatalEngineError: Wasi-ErrNo {:?}.", _0)]
    WASIError(#[source(error)] wasi_types::ErrNo),
    /// anyhow Error Wrapper.
    #[error(display = "FatalEngineError: anyhow Error {:?}.", _0)]
    AnyhowError(String),
    /// Wasmtime trap.
    #[error(display = "FatalEngineError: Wasmtime Trap Error {:?}.", _0)]
    WasmtimeTrapError(String),
}

/// Either the index or the name of a host call
#[derive(Debug, Serialize, Deserialize)]
pub enum HostFunctionIndexOrName {
    Index(usize),
    Name(String),
}

// Convertion from any error raised by any mutex of type <T> to FatalEngineError.
impl<T> From<std::sync::PoisonError<T>> for FatalEngineError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        FatalEngineError::FailedToObtainLock(format!("{:?}", error))
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

impl From<WasiAPIName> for FatalEngineError {
    fn from(error: WasiAPIName) -> Self {
        FatalEngineError::BadArgumentsToHostFunction {
            function_name: error,
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
/// Note that the top-level function `execute` in this crate relies on this trait.
pub trait ExecutionEngine: Send {
    /// Invokes the entry point of the WASM program `file_name`.  Will fail if
    /// the WASM program fails at runtime.  On success, returns the succ/error code
    /// returned by the WASM program entry point as an `i32` value.
    fn invoke_entry_point(
        &mut self,
        program: Vec<u8>,
        options: Options,
    ) -> Result<u32, FatalEngineError>;
}
