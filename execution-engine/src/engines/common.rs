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

use anyhow::Result;
use crate::{
    fs::{FileSystem, FileSystemResult, TryFromOrErrNo},
    engines::strace::Strace,
    Options,
};
use byteorder::{LittleEndian, ReadBytesExt};
use err_derive::Error;
use platform_services::{getclockres, getclocktime, getrandom, result};
use serde::{Deserialize, Serialize};
use std::{
    convert::AsMut, convert::AsRef, convert::TryFrom, io::Cursor, marker::PhantomData, mem,
    mem::size_of, ops::Deref, ops::DerefMut, slice, slice::from_raw_parts,
    slice::from_raw_parts_mut, string::String, vec::Vec,
};
use strum_macros::{EnumString, IntoStaticStr};
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
/// It can be converted between primitive numbers and enum values via `primitive` related dereive,
/// and between lowercase str and enum values via `strum`.
#[derive(
    IntoStaticStr,
    EnumString,
    Debug,
    PartialEq,
    Clone,
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
    Copy,
)]
#[strum(serialize_all = "lowercase")]
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
    #[strum(disabled)]
    _LAST,
}

/// List of Veracruz API.
#[derive(
    IntoStaticStr,
    EnumString,
    Debug,
    PartialEq,
    Clone,
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
    Copy,
)]
#[strum(serialize_all = "lowercase")]
pub enum VeracruzAPIName {
    FD_CREATE,
}

////////////////////////////////////////////////////////////////////////////////
// Miscellanea that doesn't fit elsewhere.
////////////////////////////////////////////////////////////////////////////////

/// Unpack a sequence of `bytes` and return a `T`.
pub trait Unpack: Sized {
    /// Size in bytes of the structure in the Wasm memory space. Note that this
    /// may be different than the resulting type since it is in a different
    /// memory space on a machine that likely has different pointer sizes.
    const SIZE: u32;

    /// Unpack the `T`
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

/// A trait for slices of memory that MemoryHandler operates on
///
/// Note! This is not the same as just AsRef<[u8]>!
///
/// MemorySlice is an AsRef<[u8]> with the additional requirement that
/// the underlying type is movable even when references are borrowed.
///
/// This is true for most types you may want to implement MemorySlice for,
/// such as `&[u8]`, `MutexGuard<[u8]>`, or even `Vec<u8>`. But this will fail
/// if your as_ref implementation returns references into the original struct,
/// which is allowed for AsRef<[u8]>, such as in the case of `[u8; 128]`.
///
/// Of course, this behavior is invalid for normal Rust references, since
/// preventing underlying data moves is the whole point of the borrow-checker
/// in the first place. So we need to access the underlying data through
/// pointers or reborrowed dereferences in order to create disjoint lifetimes.
///
/// This means implementors of MemorySlice will most like require unsafe code.
///
/// ---
///
/// In exchange for the requirement that the underlying type is movable,
/// consumers of MemorySlice promise to manually enforce the expected lifetime
/// of the MemorySlice. That is, accesses to the underlying borrows are only
/// legal while the MemorySlice is allocated.
///
/// To help with this, we introduce a new wrapper, Bound<'a, T>, for explicitly
/// limiting the lifetime of traits like MemorySlice.
///
/// So, while we can't leverage Rust's borrow checker to enforce these
/// lifetimes, we can at least ensure that the proper lifetimes are enforced
/// for any code that depends on MemoryHandler.
///
pub trait MemorySlice: AsRef<[u8]> {
    #[inline]
    fn as_raw_parts(&self) -> (*const u8, usize) {
        let ref_ = self.as_ref();
        (ref_.as_ptr(), ref_.len())
    }
}

/// A trait for slices of mutable memory that MemoryHandler operates on
///
/// Note! This is not the same as just AsMut<[u8]>!
///
/// See MemorySlice for more info
///
pub trait MemorySliceMut: AsMut<[u8]> {
    #[inline]
    fn as_raw_parts_mut(&mut self) -> (*mut u8, usize) {
        let ref_ = self.as_mut();
        (ref_.as_mut_ptr(), ref_.len())
    }
}

impl MemorySlice for &'static [u8] {}
impl MemorySliceMut for &'static mut [u8] {}

/// Bound<'a, T> is a wrappper that explicitly enforces unrelated lifetimes
/// on objects
///
/// It combines PhantomData and Deref to provide a simple wrapper that is
/// garaunteed by the borrow checker to not outlive the provided lifetime.
///
/// This wrapper is useful for reintroducing lifetimes that have been stripped
/// away be unsafe code.
///
#[derive(Debug, Copy, Clone)]
pub struct Bound<'a, T>(T, PhantomData<&'a T>);

impl<'a, T> Bound<'a, T> {
    #[inline]
    pub fn new(t: T) -> Self {
        Self(t, PhantomData)
    }
}

impl<'a, T> Deref for Bound<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

/// BoundMut<'a, T> is a wrappper that explicitly enforces unrelated lifetimes
/// on objects
///
/// It combines PhantomData and DerefMut to provide a simple wrapper that is
/// garaunteed by the borrow checker to not outlive the provided lifetime.
///
/// This wrapper is useful for reintroducing lifetimes that have been stripped
/// away be unsafe code.
///
#[derive(Debug)]
pub struct BoundMut<'a, T>(T, PhantomData<&'a mut T>);

impl<'a, T> BoundMut<'a, T> {
    #[inline]
    pub fn new(t: T) -> Self {
        Self(t, PhantomData)
    }
}

impl<'a, T> Deref for BoundMut<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<'a, T> DerefMut for BoundMut<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Number of iovecs to store internally before needing dynamic memory
const IOVECSLICES_SOO_COUNT: usize = 2;

/// A type wrapping an array of IoVecs as directly-accessible slices.
///
/// This indirection is needed to hold the MemoryHandler::Slice type which
/// needs to be stored somewhere
///
/// This may allocate, though most iovecs are fairly small. As an extra
/// optimization, if there are only 1 or 2 iovecs, these are stored directly
/// in the struct with no allocation. 1 iovec is the most common, though
/// 2 iovecs is used sometimes for things like appending newlines to stdout.
/// At the time of writing I have never seen >2 iovecs used in a call, though
/// it's certainly possible for aggresively optimized io.
///
pub struct IoVecSlices<'a, R> {
    _ref: R,
    slices: IoVecSlicesStorage<'a>,
}

enum IoVecSlicesStorage<'a> {
    Small([Option<&'a [u8]>; IOVECSLICES_SOO_COUNT]),
    Large(Vec<&'a [u8]>),
}

impl<'a, R> AsRef<[&'a [u8]]> for IoVecSlices<'a, R> {
    fn as_ref(&self) -> &[&'a [u8]] {
        match &self.slices {
            IoVecSlicesStorage::Small(arr) => {
                // looks a bit scary, but is just casting our `[Option<&[u8]>; 2]`
                // into a `&[&[u8]]`. This is perfectly valid Rust, though requires
                // unsafety to do this without memory allocation.
                let len = arr.iter().take_while(|x| x.is_some()).count();
                unsafe { slice::from_raw_parts(arr.as_ptr() as *const &'a [u8], len) }
            }
            IoVecSlicesStorage::Large(vec) => &vec,
        }
    }
}

/// A type wrapping a mutable array of IoVecs as directly-accessible slices.
///
/// This indirection is needed to hold the MemoryHandler::SliceMut type which
/// needs to be stored somewhere
///
/// This may allocate, though most iovecs are fairly small. As an extra
/// optimization, if there are only 1 or 2 iovecs, these are stored directly
/// in the struct with no allocation. 1 iovec is the most common, though
/// 2 iovecs is used sometimes for things like appending newlines to stdout.
/// At the time of writing I have never seen >2 iovecs used in a call, though
/// it's certainly possible for aggresively optimized io.
///
pub struct IoVecSlicesMut<'a, R> {
    _ref: R,
    slices: IoVecSlicesMutStorage<'a>,
}

enum IoVecSlicesMutStorage<'a> {
    Small([Option<&'a mut [u8]>; IOVECSLICES_SOO_COUNT]),
    Large(Vec<&'a mut [u8]>),
}

impl<'a, R> AsMut<[&'a mut [u8]]> for IoVecSlicesMut<'a, R> {
    fn as_mut(&mut self) -> &mut [&'a mut [u8]] {
        match &mut self.slices {
            IoVecSlicesMutStorage::Small(arr) => {
                // looks a bit scary, but is just casting our `[Option<&[u8]>; 2]`
                // into a `&[&[u8]]`. This is perfectly valid Rust, though requires
                // unsafety to do this without memory allocation.
                let len = arr.iter().take_while(|x| x.is_some()).count();
                unsafe { slice::from_raw_parts_mut(arr.as_mut_ptr() as *mut &'a mut [u8], len) }
            }
            IoVecSlicesMutStorage::Large(ref mut vec) => vec,
        }
    }
}

/// A MemoryHandler trait for interacting with the wasm memory space.
///
/// The API here is a bit tricky because we want to be able to leverage
/// direct access to linear memory if available, and this is provided in
/// different ways by different engines.
///
/// To make this extra confusing, we would normally use GATs to implement
/// this, but they are unfinished and only available on nightly. So instead
/// we need to use a bit of unsafe code in order to provide the correct
/// lifetimes.
///
/// As a user, don't worry! The resulting API should be completely safe to use
/// within Rust's rules. As an implementor maybe worry a little bit.
///
/// ---
///
/// At minimum, an implementation must implement `get_slice`, `get_slice_mut`,
/// and `get_size. Without GATs, we can't describe the correct lifetimes in
/// this trait, so instead we require that `get_slice` and `get_slice` return
/// associated types that implement a "lifetime-less" MemorySlice trait. It's
/// up to the implementor to satisfy this, which most likely means unsafe code
/// going through a pointer-type-cast in order to create a disjoint lifetime.
///
/// To keep this from just being completely unsafe, we reintroduce the lifetime
/// requirements with the Bound and BoundMut wrappers. These wrappers ensure
/// the structure remains allocated for the original lifetime, but in a scope
/// where we can describe the lifetime in the MemoryHandler trait.
///
/// ---
///
/// In addition to all this, MemorySlice and MemorySliceMut have a special
/// requirement that the underlying struct is movable even behind a reference.
/// This is described in more detail in the documentation of MemorySlice, and
/// is required for the self-referential slices used in IoVecSlice and
/// IoVecSliceMut without an unnecessary memory allocation.
///
/// ---
///
/// NOTE: we purposely choose u32 here as the execution engine is likely
/// received u32 as parameters.
///
pub trait MemoryHandler {
    /// A type representing a direct reference to memory
    ///
    /// This may both lock the underlying engine and allocate memory (if the
    /// engines underlying memory is not directly accessible). These should
    /// generally be short-lived to pass to other APIs.
    ///
    /// Note these have an additional requirement that the underlying type
    /// be movable even when borrowed! See MemorySlice for more info.
    ///
    type Slice: MemorySlice;

    /// A type representing a direct mutable reference to memory
    ///
    /// This may both lock the underlying engine and allocate memory (if the
    /// engines underlying memory is not directly accessible). These should
    /// generally be short-lived to pass to other APIs.
    ///
    /// Note these have an additional requirement that the underlying type
    /// be movable even when borrowed! See MemorySliceMut for more info.
    ///
    type SliceMut: MemorySliceMut;

    /// Get an immutable slice of the memory
    ///
    /// The resulting type can be used as an AsRef<[u8]>, but is explicitly
    /// bounded such that it can only be used in the lifetime of the underlying
    /// MemoryHandler.
    ///
    fn get_slice<'a>(
        &'a self,
        address: u32,
        length: u32,
    ) -> FileSystemResult<Bound<'a, Self::Slice>>;

    /// Get a mutable slice of the memory
    ///
    /// The resulting type can be used as an AsMut<[u8]>, but is explicitly
    /// bounded such that it can only be used in the lifetime of the underlying
    /// MemoryHandler.
    ///
    fn get_slice_mut<'a>(
        &'a mut self,
        address: u32,
        length: u32,
    ) -> FileSystemResult<BoundMut<'a, Self::SliceMut>>;

    /// Get the size of the underlying memory
    fn get_size(&self) -> FileSystemResult<u32>;

    /// Write the `buffer` to `address`.
    fn write_buffer(&mut self, address: u32, buffer: &[u8]) -> FileSystemResult<()> {
        self.get_slice_mut(address, u32::try_from_or_errno(buffer.len())?)?
            .as_mut()
            .copy_from_slice(buffer);
        Ok(())
    }

    /// Read into the `buffer` from `address`.
    fn read_buffer(&self, address: u32, buffer: &mut [u8]) -> FileSystemResult<()> {
        buffer.copy_from_slice(
            self.get_slice(address, u32::try_from_or_errno(buffer.len())?)?
                .as_ref(),
        );
        Ok(())
    }

    /// Reads a string at `address` of `length` from the runtime state's memory,
    /// starting at base address `address`.  If it fails, return ErrNo.
    fn read_cstring(&self, address: u32, length: u32) -> FileSystemResult<String> {
        let mut bytes = vec![0u8; usize::try_from_or_errno(length)?];
        self.read_buffer(address, &mut bytes)?;
        let rst = String::from_utf8(bytes).map_err(|_e| ErrNo::IlSeq)?;
        Ok(rst)
    }

    /// The default implementation for reading a u16 from `address`.
    fn read_u16(&self, address: u32) -> FileSystemResult<u16> {
        let mut bytes = [0u8; 2];
        self.read_buffer(address, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// The default implementation for writing a u32 to `address`.
    fn write_u32(&mut self, address: u32, number: u32) -> FileSystemResult<()> {
        self.write_buffer(address, &u32::to_le_bytes(number))
    }

    /// The default implementation for reading a u32 from `address`.
    fn read_u32(&self, address: u32) -> FileSystemResult<u32> {
        let mut bytes = [0u8; 4];
        self.read_buffer(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// The default implementation for writing a u64 to `address`.
    fn write_u64(&mut self, address: u32, number: u64) -> FileSystemResult<()> {
        self.write_buffer(address, &u64::to_le_bytes(number))
    }

    /// The default implementation for reading a u64 from `address`.
    fn read_u64(&self, address: u32) -> FileSystemResult<u64> {
        let mut bytes = [0u8; 8];
        self.read_buffer(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// The default implementation for writing any Sized struct to `address`.
    fn write_struct<T: Sized>(&mut self, address: u32, element: &T) -> FileSystemResult<()> {
        let bytes: &[u8] =
            unsafe { from_raw_parts((element as *const T) as *const u8, size_of::<T>()) };
        self.write_buffer(address, bytes)
    }

    /// The default implementation for reading any Sized struct from `address`.
    fn read_struct<T: Sized>(&self, address: u32, element: &mut T) -> FileSystemResult<()> {
        let bytes: &mut [u8] =
            unsafe { from_raw_parts_mut((element as *mut T) as *mut u8, size_of::<T>()) };
        self.read_buffer(address, bytes)
    }

    /// The default implementation for reading an Unpack from `address`.
    fn unpack<T: Unpack>(&self, address: u32) -> FileSystemResult<T> {
        let bytes = self.get_slice(address, T::SIZE)?;
        T::unpack(bytes.as_ref())
    }

    /// Unpack an array of Unpacks
    fn unpack_array<T: Unpack>(&self, address: u32, count: u32) -> FileSystemResult<Vec<T>> {
        (0..count)
            .map(|i| self.unpack(address + i * T::SIZE))
            .collect()
    }

    /// Unpack an array of iovec references
    ///
    /// The result of this is an array of slices that read directly from
    /// the underlying memory. The type is complicated in order to ensure the
    /// correct lifetime, but it can be treated as a "simple" AsRef<&[&[u8]]>.
    ///
    fn unpack_iovec<'a>(
        &'a self,
        address: u32,
        count: u32,
    ) -> FileSystemResult<IoVecSlices<'a, Bound<'a, Self::Slice>>> {
        // Just get a reference to all of memory, it's easier to manipulate
        // it this way
        let memory = self.get_slice(0, self.get_size()?)?;
        let slices = (0..count).map(|i| -> FileSystemResult<&'a [u8]> {
            let iovec = IoVec::unpack(
                &memory.as_ref()[usize::try_from_or_errno(address + i * IoVec::SIZE)?
                    ..usize::try_from_or_errno(address + (i + 1) * IoVec::SIZE)?],
            )?;

            // Ok here's the gooey center of the the copy-less iovecs. This may
            // seem unnecessary but this code finds itself on the hot-path of
            // execution the moment io gets involved.
            //
            // We want to reference directly into the engine's underlying memory
            // if possible, and MemorySlice trait takes care of that (see MemorySlice
            // for even more mess). But we take the simple reference a bit further
            // here with iovecs since we want to reference multiple slices of
            // the underlying memory while maintaining the lifetime of the original
            // MemorySlice.
            //
            // To provide this for any generic AsRef<[u8]> type requires a possibly
            // self-referential type, which gets incredibly hairy in Rust. The "safe"
            // way to do this would be to move the MemorySlice onto the heap
            // and pin it with Box::pin, though this requires memory allocation
            // and still requires pointers and a bit of unsafety to tie everything
            // together.
            //
            // In theory you could pin the MemorySlice to the stack, however it would
            // need to be allocated in the callers stack and passed to this function,
            // _greatly_ complicating this API (requiring MaybeUninit in any caller?).
            //
            // As an alternative, we can just require that the associated MemorySlice
            // type is movable, even behind a borrow. This is outside of Rust's
            // rules, but is actually reasonable for most types we would want to use
            // for MemorySlice. This requirement is satisfied by `&[u8]`,
            // `MutexGaurd<[u8]>`, and even Vec<u8>, but not by any type where `as_ref`
            // referenced data in original struct, such as `[u8; 128]`.
            //
            // ---
            //
            // Of course this sort of lifetime isn't checkable by Rust, since preventing
            // borrowed moves is the whole point of the borrow checker, so we need
            // to use a bit of unsafety to strip away the lifetime.
            //
            // Note, we still enforce the correct lifetimes for any callers! This
            // is accomplished by the `Bound` wrapper. There's more info on this
            // on the `MemorySlice` and `Bound` traits/types
            //
            let slice = &memory.as_ref()[usize::try_from_or_errno(iovec.buf)?
                ..usize::try_from_or_errno(iovec.buf + iovec.len)?];
            Ok(unsafe { mem::transmute::<&'_ [u8], &'a [u8]>(slice) })
        });

        if count <= IOVECSLICES_SOO_COUNT as u32 {
            let mut slices = slices.fuse();
            let slices = [slices.next().transpose()?, slices.next().transpose()?];
            Ok(IoVecSlices {
                _ref: memory,
                slices: IoVecSlicesStorage::Small(slices),
            })
        } else {
            let slices = slices.collect::<FileSystemResult<Vec<_>>>()?;
            Ok(IoVecSlices {
                _ref: memory,
                slices: IoVecSlicesStorage::Large(slices),
            })
        }
    }

    /// Unpack an array of mutable iovec references
    ///
    /// The result of this is an array of slices that writes directly into
    /// the underlying memory. The type is complicated in order to ensure the
    /// correct lifetime, but it can be treated as a "simple" AsMut<&mut [&mut [u8]]>.
    ///
    fn unpack_iovec_mut<'a>(
        &'a mut self,
        address: u32,
        count: u32,
    ) -> FileSystemResult<IoVecSlicesMut<'a, BoundMut<'a, Self::SliceMut>>> {
        // Just get a reference to all of memory, it's easier to manipulate
        // it this way
        let mut memory = self.get_slice_mut(0, self.get_size()?)?;
        let slices = (0..count).map(|i| -> FileSystemResult<&'a mut [u8]> {
            let iovec = IoVec::unpack(
                &memory.as_mut()[usize::try_from_or_errno(address + i * IoVec::SIZE)?
                    ..usize::try_from_or_errno(address + (i + 1) * IoVec::SIZE)?],
            )?;

            // Ok here's the gooey center of the the copy-less iovecs. This may
            // seem unnecessary but this code finds itself on the hot-path of
            // execution the moment io gets involved.
            //
            // See `unpack_iovec` for more info about what is going on here
            //

            // The _correct_ thing to do here is to
            // 1. allocate and read all iovecs first
            // 2. sort the iovecs by address
            // 3. check for overlapping ranges
            // 4. repeat slice::split_at to separate memory into sub-slices
            //    containing the slices specified by iovec
            //
            // Or we can not do that and just construct mutable slices that may
            // more may not overlap. If they overlap the worst thing that should
            // happen is malformed iovecs get malformed data back.
            //
            let slice = &mut memory.as_mut()[usize::try_from_or_errno(iovec.buf)?
                ..usize::try_from_or_errno(iovec.buf + iovec.len)?];
            Ok(unsafe { mem::transmute::<&'_ mut [u8], &'a mut [u8]>(slice) })
        });

        if count <= IOVECSLICES_SOO_COUNT as u32 {
            let mut slices = slices.fuse();
            let slices = [slices.next().transpose()?, slices.next().transpose()?];
            Ok(IoVecSlicesMut {
                _ref: memory,
                slices: IoVecSlicesMutStorage::Small(slices),
            })
        } else {
            let slices = slices.collect::<FileSystemResult<Vec<_>>>()?;
            Ok(IoVecSlicesMut {
                _ref: memory,
                slices: IoVecSlicesMutStorage::Large(slices),
            })
        }
    }

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
        &mut self,
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
    /// Whether strace is enabled.
    pub(crate) enable_strace: bool,
}

impl WasiWrapper {
    /// The name of the WASM program's entry point.
    pub(crate) const ENTRY_POINT_NAME: &'static str = "_start";
    /// The name of the WASM program's linear memory.
    pub(crate) const LINEAR_MEMORY_NAME: &'static str = "memory";
    /// The name of the containing module for all WASI imports.
    pub(crate) const WASI_SNAPSHOT_MODULE_NAME: &'static str = "wasi_snapshot_preview1";
    /// The name of the containing module for Veracruz imports.
    pub(crate) const VERACRUZ_SI_MODULE_NAME: &'static str = "veracruz_si";

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
            enable_strace: false,
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

    fn strace(&self, func: &str) -> Strace {
        Strace::func(self.enable_strace, func)
    }

    ////////////////////////////////////////////////////////////////////////////
    // WASI implementation
    ////////////////////////////////////////////////////////////////////////////

    /// The implementation of the WASI `args_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn args_get<T: MemoryHandler>(
        &self,
        memory_ref: &mut T,
        address_for_string_ptrs: u32,
        buf_address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("args_get");
        let result = (|| {
            let buffer = self
                .program_arguments
                .iter()
                .map(|arg| format!("{}\0", arg).into_bytes())
                .collect::<Vec<_>>();
            memory_ref.write_string_list(&buffer, buf_address, address_for_string_ptrs)
        })();
        strace.arg_dots();
        strace.result(result)
    }

    /// The implementation of the WASI `args_sizes_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn args_sizes_get<T: MemoryHandler>(
        &self,
        memory_ref: &mut T,
        address_for_counts: u32,
        address_for_buffer_size: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("args_sizes_get");
        let result = (|| {
            let environc = self.program_arguments.len() as u32;
            let environ_buf_size = self
                .program_arguments
                .iter()
                .fold(0, |acc, arg| acc + format!("{}\0", arg).as_bytes().len());

            memory_ref.write_u32(address_for_counts, environc)?;
            memory_ref.write_u32(address_for_buffer_size, environ_buf_size as u32)
        })();
        strace.arg_dots();
        strace.result(result)
    }

    /// The implementation of the WASI `environ_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn environ_get<T: MemoryHandler>(
        &self,
        memory_ref: &mut T,
        address_for_string_ptrs: u32,
        buf_address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("environ_get");
        let result = (|| {
            let buffer = self
                .environment_variables
                .iter()
                .map(|(key, value)| {
                    let environ = format!("{}={}\0", key, value);
                    environ.into_bytes()
                })
                .collect::<Vec<_>>();
            memory_ref.write_string_list(&buffer, buf_address, address_for_string_ptrs)
        })();
        strace.arg_dots();
        strace.result(result)
    }

    /// THe implementation of the WASI `environ_sizes_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn environ_sizes_get<T: MemoryHandler>(
        &self,
        memory_ref: &mut T,
        address_for_counts: u32,
        address_for_buffer_size: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("environ_sizes_get");
        let result = (|| {
            let environc = self.environment_variables.len() as u32;
            let environ_buf_size = self
                .environment_variables
                .iter()
                .fold(0, |acc, (key, value)| {
                    acc + format!("{}={}\0", key, value).as_bytes().len()
                });

            memory_ref.write_u32(address_for_counts, environc)?;
            memory_ref.write_u32(address_for_buffer_size, environ_buf_size as u32)
        })();
        strace.arg_dots();
        strace.result(result)
    }

    /// The implementation of the WASI `clock_res_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn clock_res_get<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        clock_id: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("clock_res_get");
        let result = (|| {
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
        })();
        strace.arg_dec(clock_id);
        strace.arg_p_u64(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `clock_time_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn clock_time_get<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        clock_id: u32,
        precision: u64,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("clock_time_get");
        let result = (|| {
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
        })();
        strace.arg_dec(clock_id);
        strace.arg_dec(precision);
        strace.arg_p_u64(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_advise` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_advise<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        fd: u32,
        offset: u64,
        len: u64,
        advice: u8,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_advise");
        let result = (|| {
            let advice: Advice = Self::decode_wasi_arg(advice)?;
            self.filesystem.fd_advise(fd.into(), offset, len, advice)
        })();
        strace.arg_dec(fd);
        strace.arg_dec(offset);
        strace.arg_dec(len);
        strace.arg_dec(advice);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_allocate` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_allocate<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        fd: u32,
        offset: u64,
        len: u64,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_allocate");
        let result = self.filesystem.fd_allocate(fd.into(), offset, len);
        strace.arg_dec(fd);
        strace.arg_dec(offset);
        strace.arg_dec(len);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_close` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_close<T: MemoryHandler>(
        &mut self,
        _memory_ref: &T,
        fd: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_close");
        let result = self.filesystem.fd_close(fd.into());
        strace.arg_dec(fd);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_datasync` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_datasync<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        fd: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_datasync");
        let result = self.filesystem.fd_datasync(fd.into());
        strace.arg_dec(fd);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_fdstat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_fdstat_get<T: MemoryHandler>(
        &self,
        memory_ref: &mut T,
        fd: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_fdstat_get");
        let result = (|| {
            let stat = self.filesystem.fd_fdstat_get(fd.into())?;
            memory_ref.write_struct(address, &stat)
        })();
        strace.arg_dec(fd);
        strace.arg_fdstat(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_fdstat_set_flags` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_fdstat_set_flags<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        fd: u32,
        flags: u16,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_fdstat_set_flags");
        let result = (|| {
            let flags: FdFlags = Self::decode_wasi_arg(flags)?;
            self.filesystem.fd_fdstat_set_flags(fd.into(), flags)
        })();
        strace.arg_dec(fd);
        strace.arg_hex(flags);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_fdstat_set_rights` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_fdstat_set_rights<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        fd: u32,
        rights_base: u64,
        rights_inheriting: u64,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_fdstat_set_rights");
        let result = (|| {
            let rights_base: Rights = Self::decode_wasi_arg(rights_base)?;
            let rights_inheriting: Rights = Self::decode_wasi_arg(rights_inheriting)?;
            self.filesystem
                .fd_fdstat_set_rights(fd.into(), rights_base, rights_inheriting)
        })();
        strace.arg_dec(fd);
        strace.arg_hex(rights_base);
        strace.arg_hex(rights_inheriting);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_filestat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_filestat_get<T: MemoryHandler>(
        &self,
        memory_ref: &mut T,
        fd: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_filestat_get");
        let result = (|| {
            let stat = self.filesystem.fd_filestat_get(fd.into());
            memory_ref.write_struct(address, &stat)
        })();
        strace.arg_dec(fd);
        strace.arg_filestat(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_filestat_set_size` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_filestat_set_size<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        fd: u32,
        size: u64,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_filestat_set_size");
        let result = self.filesystem.fd_filestat_set_size(fd.into(), size);
        strace.arg_dec(fd);
        strace.arg_dec(size);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_filestat_set_times` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_filestat_set_times<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        fd: u32,
        atime: u64,
        mtime: u64,
        fst_flag: u16,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_filestat_set_times");
        let result = (|| {
            let fst_flag: SetTimeFlags = Self::decode_wasi_arg(fst_flag)?;
            self.filesystem.fd_filestat_set_times(
                fd.into(),
                atime.into(),
                mtime.into(),
                fst_flag,
                self.filestat_time(),
            )
        })();
        strace.arg_dec(fd);
        strace.arg_dec(atime);
        strace.arg_dec(mtime);
        strace.arg_hex(fst_flag);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_pread` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_pread<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        offset: u64,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_pread");
        let result = (|| {
            let size_read = {
                let mut iovecs = memory_ref.unpack_iovec_mut(iovec_base, iovec_count)?;
                self.filesystem
                    .fd_pread(fd.into(), iovecs.as_mut(), offset)?
            };
            memory_ref.write_u32(address, size_read as u32)
        })();
        strace.arg_dec(fd);
        strace.arg_iovec(result, memory_ref, iovec_base, iovec_count, address);
        strace.arg_dec(offset);
        strace.arg_p_u32(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_prestat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_prestat_get<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_prestat_get");
        let result = (|| {
            let fd = Fd(fd);
            let pre = self.filesystem.fd_prestat_get(fd)?;
            memory_ref.write_struct(address, &pre)
        })();
        strace.arg_dec(fd);
        strace.arg_prestat_out(result, memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_prestat_dir_name` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_prestat_dir_name<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        address: u32,
        size: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_prestat_dir_name");
        let result = (|| {
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
        })();
        strace.arg_dec(fd);
        strace.arg_path(memory_ref, address, size);
        strace.arg_dec(size);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_pwrite` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_pwrite<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        offset: u64,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_pwrite");
        let result = (|| {
            let size_written = {
                let iovecs = memory_ref.unpack_iovec(iovec_base, iovec_count)?;
                self.filesystem
                    .fd_pwrite(fd.into(), iovecs.as_ref(), offset)?
            };
            memory_ref.write_u32(address, size_written as u32)
        })();
        strace.arg_dec(fd);
        strace.arg_iovec(result, memory_ref, iovec_base, iovec_count, address);
        strace.arg_dec(offset);
        strace.arg_p_u32(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_read` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_read<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_read");
        let result = (|| {
            let size_read = {
                let mut iovecs = memory_ref.unpack_iovec_mut(iovec_base, iovec_count)?;
                self.filesystem.fd_read(fd.into(), iovecs.as_mut())?
            };
            memory_ref.write_u32(address, size_read as u32)
        })();
        strace.arg_dec(fd);
        strace.arg_iovec(result, memory_ref, iovec_base, iovec_count, address);
        strace.arg_p_u32(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_readdir` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_readdir<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        mut buf_ptr: u32,
        buf_len: u32,
        cookie: u64,
        result_ptr: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_readdir");
        let result = (|| {
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
        })();
        strace.arg_dec(fd);
        strace.arg_dirents(memory_ref, buf_ptr, buf_len, result_ptr);
        strace.arg_dec(cookie);
        strace.arg_p_u32(memory_ref, result_ptr);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_renumber` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_renumber<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        old_fd: u32,
        new_fd: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_renumber");
        let result = self.filesystem.fd_renumber(old_fd.into(), new_fd.into());
        strace.arg_dec(old_fd);
        strace.arg_dec(new_fd);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_seek` function.
    pub(crate) fn fd_seek<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        offset: i64,
        whence: u8,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_seek");
        let result = (|| {
            let whence: Whence = Self::decode_wasi_arg(whence)?;
            let new_offset = self.filesystem.fd_seek(fd.into(), offset, whence)?;
            memory_ref.write_u64(address, new_offset)
        })();
        strace.arg_dec(fd);
        strace.arg_dec(offset);
        strace.arg_dec(whence);
        strace.arg_p_u64(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_sync` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn fd_sync<T: MemoryHandler>(&mut self, _: &mut T, fd: u32) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_sync");
        let result = self.filesystem.fd_sync(fd.into());
        strace.arg_dec(fd);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_tell` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_tell<T: MemoryHandler>(
        &self,
        memory_ref: &mut T,
        fd: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_tell");
        let result = (|| {
            let offset = self.filesystem.fd_tell(fd.into())?;
            memory_ref.write_u64(address, offset)
        })();
        strace.arg_dec(fd);
        strace.arg_p_u64(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `fd_write` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn fd_write<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("fd_write");
        let result = (|| {
            let size_written = {
                let iovecs = memory_ref.unpack_iovec(iovec_base, iovec_count)?;
                self.filesystem.fd_write(fd.into(), iovecs.as_ref())?
            };
            memory_ref.write_u32(address, size_written as u32)
        })();
        strace.arg_dec(fd);
        strace.arg_iovec(result, memory_ref, iovec_base, iovec_count, address);
        strace.arg_p_u32(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `path_create_directory` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_create_directory<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        path_address: u32,
        path_length: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("path_create_directory");
        let result = (|| {
            let path = memory_ref.read_cstring(path_address, path_length)?;
            self.filesystem.path_create_directory(fd.into(), path)
        })();
        strace.arg_dec(fd);
        strace.arg_path(memory_ref, path_address, path_length);
        strace.result(result)
    }

    /// The implementation of the WASI `path_filestat_get` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_filestat_get<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        flags: u32,
        path_address: u32,
        path_length: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("path_filestat_get");
        let result = (|| {
            let path = memory_ref.read_cstring(path_address, path_length)?;
            let flags: LookupFlags = Self::decode_wasi_arg(flags)?;
            let stat = self.filesystem.path_filestat_get(fd.into(), flags, path)?;
            memory_ref.write_struct(address, &stat)
        })();
        strace.arg_dec(fd);
        strace.arg_hex(flags);
        strace.arg_path(memory_ref, path_address, path_length);
        strace.arg_filestat(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `path_filestat_set_times` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_filestat_set_times<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        flags: u32,
        path_address: u32,
        path_length: u32,
        atime: u64,
        mtime: u64,
        fst_flag: u16,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("path_filestat_set_times");
        let result = (|| {
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
        })();
        strace.arg_dec(fd);
        strace.arg_hex(flags);
        strace.arg_path(memory_ref, path_address, path_length);
        strace.arg_dec(atime);
        strace.arg_dec(mtime);
        strace.arg_hex(fst_flag);
        strace.result(result)
    }

    /// The implementation of the WASI `path_link` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_link<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        old_fd: u32,
        old_flags: u32,
        old_address: u32,
        old_path_len: u32,
        new_fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("path_link");
        let result = (|| {
            let old_flags: LookupFlags = Self::decode_wasi_arg(old_flags)?;
            let old_path = memory_ref.read_cstring(old_address, old_path_len)?;
            let new_path = memory_ref.read_cstring(new_address, new_path_len)?;
            self.filesystem
                .path_link(old_fd.into(), old_flags, old_path, new_fd.into(), new_path)
        })();
        strace.arg_dec(old_fd);
        strace.arg_hex(old_flags);
        strace.arg_path(memory_ref, old_address, old_path_len);
        strace.arg_dec(new_fd);
        strace.arg_path(memory_ref, new_address, new_path_len);
        strace.result(result)
    }

    /// The implementation of the WASI `path_open` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_open<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
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
        let mut strace = self.strace("path_open");
        let result = (|| {
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
        })();
        strace.arg_dec(fd);
        strace.arg_hex(dir_flags);
        strace.arg_path(memory_ref, path_address, path_length);
        strace.arg_hex(oflags);
        strace.arg_rights(fs_rights_base);
        strace.arg_rights(fs_rights_inheriting);
        strace.arg_hex(fd_flags);
        strace.arg_p_u32(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `path_readlink` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_readlink<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        path_address: u32,
        path_length: u32,
        buf: u32,
        buf_len: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("path_readlink");
        let result = (|| {
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
        })();
        strace.arg_dec(fd);
        strace.arg_path(memory_ref, path_address, path_length);
        strace.arg_path(memory_ref, buf, buf_len);
        strace.arg_p_u32(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `path_remove_directory` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_remove_directory<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        path_address: u32,
        path_length: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("path_remove_directory");
        let result = (|| {
            let path = memory_ref.read_cstring(path_address, path_length)?;
            self.filesystem.path_remove_directory(fd.into(), path)
        })();
        strace.arg_dec(fd);
        strace.arg_path(memory_ref, path_address, path_length);
        strace.result(result)
    }

    /// The implementation of the WASI `path_rename` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_rename<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        old_fd: u32,
        old_address: u32,
        old_path_len: u32,
        new_fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("path_rename");
        let result = (|| {
            let old_path = memory_ref.read_cstring(old_address, old_path_len)?;
            let new_path = memory_ref.read_cstring(new_address, new_path_len)?;
            self.filesystem
                .path_rename(old_fd.into(), old_path, new_fd.into(), new_path)
        })();
        strace.arg_dec(old_fd);
        strace.arg_path(memory_ref, old_address, old_path_len);
        strace.arg_dec(new_fd);
        strace.arg_path(memory_ref, new_address, old_path_len);
        strace.result(result)
    }

    /// The implementation of the WASI `path_symlink` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_symlink<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        old_address: u32,
        old_path_len: u32,
        fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("path_symlink");
        let result = (|| {
            let old_path = memory_ref.read_cstring(old_address, old_path_len)?;
            let new_path = memory_ref.read_cstring(new_address, new_path_len)?;
            self.filesystem.path_symlink(old_path, fd.into(), new_path)
        })();
        strace.arg_path(memory_ref, old_address, old_path_len);
        strace.arg_dec(fd);
        strace.arg_path(memory_ref, new_address, old_path_len);
        strace.result(result)
    }

    /// The implementation of the WASI `path_unlink_file` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn path_unlink_file<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        fd: u32,
        path_address: u32,
        path_len: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("path_unlink_file");
        let result = (|| {
            let path = memory_ref.read_cstring(path_address, path_len)?;
            self.filesystem.path_unlink_file(fd.into(), path)
        })();
        strace.arg_dec(fd);
        strace.arg_path(memory_ref, path_address, path_len);
        strace.result(result)
    }

    /// The implementation of the WASI `poll_oneoff` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn poll_oneoff<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        subscriptions: u32,
        events: u32,
        size: u32,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("poll_oneoff");
        let result = (|| {
            let subscriptions = memory_ref.unpack_array::<Subscription>(subscriptions, size)?;
            let events = memory_ref.unpack_array::<Event>(events, size)?;
            let rst = self.filesystem.poll_oneoff(subscriptions, events)?;
            memory_ref.write_u32(address, rst)
        })();
        strace.arg_subscriptions(memory_ref, subscriptions, size);
        strace.arg_events(memory_ref, events, size);
        strace.arg_p_u32(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `proc_exit` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn proc_exit<T: MemoryHandler>(&mut self, _: &mut T, exit_code: u32) {
        let _strace = self.strace("proc_exit");
        self.exit_code = Some(exit_code)
    }

    /// The implementation of the WASI `proc_raise` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn proc_raise<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        signal: u8,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("proc_raise");
        let result = (|| {
            let _signal: Signal = Self::decode_wasi_arg(signal)?;
            Err(ErrNo::NoSys)
        })();
        strace.arg_dec(signal);
        strace.result(result)
    }

    /// The implementation of the WASI `sched_yield` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    #[inline]
    pub(crate) fn sched_yield<T: MemoryHandler>(&mut self, _: &mut T) -> FileSystemResult<()> {
        let mut strace = self.strace("sched_yield");
        strace.result(Err(ErrNo::NoSys))
    }

    pub(crate) fn random_get<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        buf_ptr: u32,
        length: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("random_get");
        let result = (|| {
            let mut bytes = vec![0; length as usize];
            if getrandom(&mut bytes).is_success() {
                memory_ref.write_buffer(buf_ptr, &bytes)
            } else {
                Err(ErrNo::NoSys)
            }
        })();
        strace.arg_buffer(memory_ref, buf_ptr, length);
        strace.result(result)
    }

    /// The implementation of the WASI `sock_recv` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn sock_recv<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        socket: u32,
        ri_address: u32,
        ri_len: u32,
        ri_flag: u16,
        ro_data_len: u32,
        ro_flag: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("sock_recv");
        let result = (|| {
            let (size_read, ro_flags) = {
                let mut iovecs = memory_ref.unpack_iovec_mut(ri_address, ri_len)?;
                let ri_flags: RiFlags = Self::decode_wasi_arg(ri_flag)?;
                self.filesystem
                    .sock_recv(socket.into(), iovecs.as_mut(), ri_flags)?
            };
            let ro_flags = RoFlags::empty() | ro_flags;
            memory_ref.write_u32(ro_data_len, size_read as u32)?;
            memory_ref.write_buffer(ro_flag, &u16::to_le_bytes(ro_flags.bits()))
        })();
        strace.arg_dec(socket);
        strace.arg_iovec(result, memory_ref, ri_address, ri_len, ro_data_len);
        strace.arg_hex(ri_flag);
        strace.arg_p_u32(memory_ref, ro_data_len);
        strace.arg_p_u16_hex(memory_ref, ro_flag);
        strace.result(result)
    }

    /// The implementation of the WASI `sock_send` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn sock_send<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        socket: u32,
        si_address: u32,
        si_len: u32,
        si_flag: u16,
        address: u32,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("sock_send");
        let result = (|| {
            let size_written = {
                let iovecs = memory_ref.unpack_iovec(si_address, si_len)?;
                let si_flags: SiFlags = Self::decode_wasi_arg(si_flag)?;
                self.filesystem
                    .sock_send(socket.into(), iovecs.as_ref(), si_flags)?
            };
            memory_ref.write_u32(address, size_written as u32)
        })();
        strace.arg_iovec(result, memory_ref, si_address, si_len, address);
        strace.arg_hex(si_flag);
        strace.arg_p_u32(memory_ref, address);
        strace.result(result)
    }

    /// The implementation of the WASI `sock_recv` function. It requires an extra `memory_ref` to
    /// interact with the execution engine.
    pub(crate) fn sock_shutdown<T: MemoryHandler>(
        &mut self,
        _: &mut T,
        socket: u32,
        sd_flag: u8,
    ) -> FileSystemResult<()> {
        let mut strace = self.strace("sock_shutdown");
        let result = (|| {
            let sd_flag: SdFlags = Self::decode_wasi_arg(sd_flag)?;
            self.filesystem.sock_shutdown(socket.into(), sd_flag)
        })();
        strace.arg_dec(socket);
        strace.arg_hex(sd_flag);
        strace.result(result)
    }

    /// This function, added for Veracruz, creates a new anonymous file.
    pub(crate) fn fd_create<T: MemoryHandler>(
        &mut self,
        memory_ref: &mut T,
        address: u32,
    ) -> FileSystemResult<()> {
        let new_fd = self.filesystem.fd_create()?;
        memory_ref.write_u32(address, new_fd.into())
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
    //#[error(display = "FatalEngineError: Failed to obtain lock {:?}.", _0)]
    //FailedToObtainLock(String),
    #[error(display = "FatalEngineError: Failed to obtain lock on the engine or components of the engine.")]
    FailedLockEngine,
    #[error(display = "FatalEngineError: Failed to obtain lock on the file system.")]
    FailedLockFileSystem,
    #[error(display = "FatalEngineError: Wasm engine trap: {:?}", _0)]
    Trap(String),
}

/// Either the index or the name of a host call
#[derive(Debug, Serialize, Deserialize)]
pub enum HostFunctionIndexOrName {
    Index(usize),
    Name(String),
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
    ) -> Result<u32>;
}
