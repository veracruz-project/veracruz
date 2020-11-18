//! The Veracruz host interface
//!
//! Abstracts over the Veracruz ABI and provides useful, derived functionality.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryFrom;
use core::fmt;
use pinecone;

///////////////////////////////////////////////////////////////////////////////
// The raw H-call error return type.
///////////////////////////////////////////////////////////////////////////////

/// Return codes from the H-calls.  A H-call either:
///
///   - Successfully executes, producing a result, in which case
///     `HCallReturnCode::Success` is returned,
///   - Fails for some reason, in which case an appropriate error code is
///     returned.
///
#[derive(Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HCallReturnCode<T> {
    /// Successful execution of the H-call
    Success(T),
    /// Generic, or underspecified, failure
    ErrorGeneric,
    /// Failure related to the number of data sources, e.g. an invalid index
    ErrorDataSourceCount,
    /// Failure related to the size of data sources, e.g. a buffer size issue
    ErrorDataSourceSize,
    /// Failure related to parameters passed to a function, e.g. passing a
    /// negative value where an unsigned value is expected, or similar
    ErrorBadInput,
    /// Failure due to the program trying to provide a second output when one
    /// has already been provided
    ErrorResultAlreadyWritten,
    /// A call to a trusted platform service (e.g. `getrandom`) is not available
    /// on this platform.
    ErrorServiceUnavailable,
}

///////////////////////////////////////////////////////////////////////////////
// Type implementation
///////////////////////////////////////////////////////////////////////////////

fn expect_failed(msg: &str) -> ! {
    panic!("{}", msg)
}

fn expect_error_failed<T: fmt::Debug>(msg: &str, val: &T) {
    panic!("{}: {:?}", msg, val)
}

impl<T> HCallReturnCode<T> {
    ///////////////////////////////////////////////////////////////////////////
    // Querying the contained values
    ///////////////////////////////////////////////////////////////////////////

    /// Returns `true` if the status code is a `HCallReturnCode::Success`
    /// value.
    #[inline]
    pub fn is_success(&self) -> bool {
        match self {
            HCallReturnCode::Success(_result) => true,
            _otherwise => false,
        }
    }

    #[inline]
    pub fn is_error_generic(&self) -> bool {
        match self {
            HCallReturnCode::ErrorGeneric => true,
            _otherwise => false,
        }
    }

    #[inline]
    pub fn is_error_data_source_count(&self) -> bool {
        match self {
            HCallReturnCode::ErrorDataSourceCount => true,
            _otherwise => false,
        }
    }

    #[inline]
    pub fn is_error_data_source_size(&self) -> bool {
        match self {
            HCallReturnCode::ErrorDataSourceSize => true,
            _otherwise => false,
        }
    }

    #[inline]
    pub fn is_error_bad_input(&self) -> bool {
        match self {
            HCallReturnCode::ErrorBadInput => true,
            _otherwise => false,
        }
    }

    #[inline]
    pub fn is_error_service_unavailable(&self) -> bool {
        match self {
            HCallReturnCode::ErrorServiceUnavailable => true,
            _otherwise => false,
        }
    }

    #[inline]
    pub fn is_error(&self) -> bool {
        !self.is_success()
    }

    #[inline]
    pub fn unwrap(self) -> T {
        match self {
            HCallReturnCode::Success(result) => result,
            _otherwise => panic!("unwrap called on non-success constructor"),
        }
    }

    #[inline]
    pub fn unwrap_or(self, default: T) -> T {
        match self {
            HCallReturnCode::Success(result) => result,
            _otherwise => default,
        }
    }

    #[inline]
    pub fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T {
        match self {
            HCallReturnCode::Success(result) => result,
            _otherwise => f(),
        }
    }

    #[inline]
    pub fn expect(self, message: &str) -> T {
        match self {
            HCallReturnCode::Success(result) => result,
            _otherwise => expect_failed(message),
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    // Transforming contained values
    //////////////////////////////////////////////////////////////////////////////

    #[inline]
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> HCallReturnCode<U> {
        match self {
            HCallReturnCode::Success(result) => HCallReturnCode::Success(f(result)),
            HCallReturnCode::ErrorGeneric => HCallReturnCode::ErrorGeneric,
            HCallReturnCode::ErrorDataSourceCount => HCallReturnCode::ErrorDataSourceCount,
            HCallReturnCode::ErrorDataSourceSize => HCallReturnCode::ErrorDataSourceSize,
            HCallReturnCode::ErrorBadInput => HCallReturnCode::ErrorBadInput,
            HCallReturnCode::ErrorResultAlreadyWritten => {
                HCallReturnCode::ErrorResultAlreadyWritten
            }
            HCallReturnCode::ErrorServiceUnavailable => HCallReturnCode::ErrorServiceUnavailable,
        }
    }

    #[inline]
    pub fn map_or<U, F: FnOnce(T) -> U>(self, default: U, f: F) -> U {
        match self {
            HCallReturnCode::Success(result) => f(result),
            _otherwise => default,
        }
    }

    #[inline]
    pub fn map_or_else<U, D: FnOnce() -> U, F: FnOnce(T) -> U>(self, default: D, f: F) -> U {
        match self {
            HCallReturnCode::Success(result) => f(result),
            _otherwise => default(),
        }
    }

    #[inline]
    pub fn ok_or<E>(self, err: E) -> Result<T, E> {
        match self {
            HCallReturnCode::Success(result) => Ok(result),
            _otherwise => Err(err),
        }
    }

    #[inline]
    pub fn ok_or_else<E, F: FnOnce() -> E>(self, err: F) -> Result<T, E> {
        match self {
            HCallReturnCode::Success(result) => Ok(result),
            _otherwise => Err(err()),
        }
    }

    #[inline]
    pub fn and_then<U, F: FnOnce(T) -> HCallReturnCode<U>>(self, f: F) -> HCallReturnCode<U> {
        match self {
            HCallReturnCode::Success(result) => f(result),
            HCallReturnCode::ErrorGeneric => HCallReturnCode::ErrorGeneric,
            HCallReturnCode::ErrorDataSourceCount => HCallReturnCode::ErrorDataSourceCount,
            HCallReturnCode::ErrorDataSourceSize => HCallReturnCode::ErrorDataSourceSize,
            HCallReturnCode::ErrorBadInput => HCallReturnCode::ErrorBadInput,
            HCallReturnCode::ErrorResultAlreadyWritten => {
                HCallReturnCode::ErrorResultAlreadyWritten
            }
            HCallReturnCode::ErrorServiceUnavailable => HCallReturnCode::ErrorServiceUnavailable,
        }
    }

    #[inline]
    pub fn or_else<F: FnOnce() -> HCallReturnCode<T>>(self, f: F) -> HCallReturnCode<T> {
        match &self {
            HCallReturnCode::Success(_result) => self,
            _otherwise => f(),
        }
    }
}

impl<T: Copy> HCallReturnCode<&mut T> {
    #[inline]
    pub fn copied(self) -> HCallReturnCode<T> {
        self.map(|&mut t| t)
    }
}

impl<T: Clone> HCallReturnCode<&mut T> {
    #[inline]
    pub fn cloned(self) -> HCallReturnCode<T> {
        self.map(|t| t.clone())
    }
}

impl<T: fmt::Debug> HCallReturnCode<T> {
    #[inline]
    pub fn expect_error_generic(self, msg: &str) {
        match self {
            HCallReturnCode::ErrorGeneric => (),
            otherwise => expect_error_failed(msg, &otherwise),
        }
    }

    #[inline]
    pub fn expect_error_data_source_count(self, msg: &str) {
        match self {
            HCallReturnCode::ErrorDataSourceCount => (),
            otherwise => expect_error_failed(msg, &otherwise),
        }
    }

    #[inline]
    pub fn expect_error_data_source_size(self, msg: &str) {
        match self {
            HCallReturnCode::ErrorDataSourceSize => (),
            otherwise => expect_error_failed(msg, &otherwise),
        }
    }

    #[inline]
    pub fn expect_error_bad_input(self, msg: &str) {
        match self {
            HCallReturnCode::ErrorBadInput => (),
            otherwise => expect_error_failed(msg, &otherwise),
        }
    }

    #[inline]
    pub fn expect_error_result_already_written(self, msg: &str) {
        match self {
            HCallReturnCode::ErrorResultAlreadyWritten => (),
            otherwise => expect_error_failed(msg, &otherwise),
        }
    }
}

impl<T: Default> HCallReturnCode<T> {
    #[inline]
    pub fn unwrap_or_default(self) -> T {
        match self {
            HCallReturnCode::Success(result) => result,
            _otherwise => Default::default(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Trait implementations
///////////////////////////////////////////////////////////////////////////////

impl<T: Clone> Clone for HCallReturnCode<T> {
    #[inline]
    fn clone(&self) -> Self {
        match self {
            HCallReturnCode::Success(result) => HCallReturnCode::Success(result.clone()),
            HCallReturnCode::ErrorGeneric => HCallReturnCode::ErrorGeneric,
            HCallReturnCode::ErrorDataSourceCount => HCallReturnCode::ErrorDataSourceCount,
            HCallReturnCode::ErrorDataSourceSize => HCallReturnCode::ErrorDataSourceSize,
            HCallReturnCode::ErrorBadInput => HCallReturnCode::ErrorBadInput,
            HCallReturnCode::ErrorResultAlreadyWritten => {
                HCallReturnCode::ErrorResultAlreadyWritten
            }
            HCallReturnCode::ErrorServiceUnavailable => HCallReturnCode::ErrorServiceUnavailable,
        }
    }

    #[inline]
    fn clone_from(&mut self, source: &Self) {
        match (self, source) {
            (HCallReturnCode::Success(dst), HCallReturnCode::Success(src)) => dst.clone_from(src),
            (dst, src) => *dst = src.clone(),
        }
    }
}

impl<T> Default for HCallReturnCode<T> {
    /// Returns `HCallReturnCode::ErrorGeneric`.
    #[inline]
    fn default() -> HCallReturnCode<T> {
        HCallReturnCode::ErrorGeneric
    }
}

impl<T> From<T> for HCallReturnCode<T> {
    #[inline]
    fn from(x: T) -> HCallReturnCode<T> {
        HCallReturnCode::Success(x)
    }
}

///////////////////////////////////////////////////////////////////////////////
// The raw H-calls
///////////////////////////////////////////////////////////////////////////////

extern "C" {
    /// Returns the number of input sources that are available to this program
    fn __veracruz_hcall_input_count(count: *mut u8) -> i32;
    /// Returns the size of input source N, in bytes
    fn __veracruz_hcall_input_size(index: u32, size: *mut u8) -> i32;
    /// Reads input source N into the given buffer
    fn __veracruz_hcall_read_input(index: u32, buffer: *mut u8, size: u32) -> i32;
    /// Writes the program's output to the host
    fn __veracruz_hcall_write_output(buffer: *const u8, size: u32) -> i32;
    /// Fills a buffer with random bytes taken from a platform-specific trusted
    /// entropy source.
    fn __veracruz_hcall_getrandom(buffer: *mut u8, size: u32) -> i32;
    /// Reads the previous result into the given buffer
    fn __veracruz_hcall_read_previous_result(buffer: *mut u8, size: u32) -> i32;
    /// Reads the size of previous result encoded by pinecone
    fn __veracruz_hcall_previous_result_size(count: *mut u8) -> i32;
    /// Returns the number of stream sources that are available to this program
    fn __veracruz_hcall_stream_count(count: *mut u8) -> i32;
    /// Returns the size of stream source N, in bytes
    fn __veracruz_hcall_stream_size(index: u32, size: *mut u8) -> i32;
    /// Reads stream source N into the given buffer
    fn __veracruz_hcall_read_stream(index: u32, buffer: *mut u8, size: u32) -> i32;
}

///////////////////////////////////////////////////////////////////////////////
// Utility functions
///////////////////////////////////////////////////////////////////////////////

/// Lifts a `u32` value into a `HCallReturnCode`.  In the case where the
/// `u32` value codes `HCallReturnCode::Success` the supplied element
/// `t` is used as the wrapped value.
///
/// Fails with `None` if the `u32` value does not code a legitimate enum
/// value.
fn lift<T>(code: i32, t: T) -> Option<HCallReturnCode<T>> {
    if code == 0 {
        Some(HCallReturnCode::Success(t))
    } else if code == -1 {
        Some(HCallReturnCode::ErrorGeneric)
    } else if code == -2 {
        Some(HCallReturnCode::ErrorDataSourceCount)
    } else if code == -3 {
        Some(HCallReturnCode::ErrorDataSourceSize)
    } else if code == -4 {
        Some(HCallReturnCode::ErrorBadInput)
    } else if code == -5 {
        Some(HCallReturnCode::ErrorResultAlreadyWritten)
    } else if code == -6 {
        Some(HCallReturnCode::ErrorServiceUnavailable)
    } else {
        None
    }
}

///////////////////////////////////////////////////////////////////////////////
// A thin wrapper around the H-calls
///////////////////////////////////////////////////////////////////////////////

/// Returns the number of input sources that are available to the program.
///
/// The H-call does not fail.
pub fn input_count() -> u32 {
    let retcode;
    let mut buffer = vec![0u8; 4];

    unsafe {
        retcode = __veracruz_hcall_input_count(buffer.as_mut_ptr() as *mut u8);
    };

    assert_eq!(retcode, 0);

    LittleEndian::read_u32(&buffer)
}

/// Returns the size, in bytes, of the input source indexed by `index`.
///
/// The H-call fails for only the following reasons:
///
/// 1. Fails if the `index` value is larger than the number of input sources
/// available to the program with `HCallReturnCode::ErrorDataSourceCount`.
pub fn input_size(index: u32) -> HCallReturnCode<u32> {
    let retcode;
    let mut buffer = vec![0u8; 4];

    unsafe { retcode = __veracruz_hcall_input_size(index, buffer.as_mut_ptr() as *mut u8) };

    lift(retcode, LittleEndian::read_u32(&buffer)).unwrap()
}

/// Reads an input, returned as a vector of `u8` values, indexed by `index`.
/// The program is assumed to understand how to parse the array of bytes
/// returned into something more meaningful, e.g. by fixing an assumed encoding
/// between data source providers and the program owner.
///
/// The H-call fails for only the following reasons:
///
/// 1. Fails if the `index` value is larger than the number of input sources
/// available to the program with `HCallReturnCode::ErrorDataSourceCount`.
pub fn read_input(index: u32) -> HCallReturnCode<Vec<u8>> {
    input_size(index).and_then(|size| {
        let mut buffer = vec![0u8; size as usize];
        let retcode;

        unsafe {
            retcode = __veracruz_hcall_read_input(index, buffer.as_mut_ptr() as *mut u8, size)
        };

        lift(retcode, buffer).unwrap()
    })
}

/// Reads all inputs, returned as a vector of vector of `u8` values.  The
/// program is assumed to understand how to parse the bytes returned into
/// something more meaningful, e.g. by fixing an assumed encoding between data
/// source providers and the program owner.
///
/// The H-call does not fail.
pub fn read_all_inputs() -> Vec<Vec<u8>> {
    let inputs = input_count();
    let mut buffer = Vec::new();

    for i in 0..inputs {
        let input = read_input(i).expect("read_all_inputs: read_input failed.");
        buffer.push(input);
    }

    buffer
}

/// Writes the `output` slice of `u8` values as output of the program.
///
/// The H-call fails for only the following reasons:
///
/// 1. Fails with `HCallReturnCode::ErrorResultAlreadyWritten` if a result has
/// already been provided to the host by the program.
/// 2. Fails with `HCallReturnCode::ErrorBadInput` if the length of `output`
/// cannot be converted to a `u32` value.
pub fn write_output(output: &[u8]) -> HCallReturnCode<()> {
    let size: u32 = match u32::try_from(output.len()) {
        Ok(size) => size,
        _otherwise => return HCallReturnCode::ErrorBadInput,
    };
    let retcode;

    unsafe {
        retcode = __veracruz_hcall_write_output(output.as_ptr() as *const u8, size);
    };

    lift(retcode, ()).unwrap()
}

/// Fills the `buffer` with a randomly-generated series of bytes taken from a
/// platform-specific trusted entropy source.
///
/// The H-call fails for only the following reasons:
///
/// 1. Fails with `HCallReturnCode::ErrorBadInput` if the length of the buffer
/// cannot be converted to a `u32` value.
pub fn getrandom(buffer: &mut [u8]) -> HCallReturnCode<()> {
    let size = match u32::try_from(buffer.len()) {
        Ok(size) => size,
        _otherwise => return HCallReturnCode::ErrorBadInput,
    };
    let retcode;

    unsafe {
        retcode = __veracruz_hcall_getrandom(buffer.as_mut_ptr() as *mut u8, size);
    }

    lift(retcode, ()).unwrap()
}

/// Returns the size of previous result
pub fn previous_result_size() -> HCallReturnCode<u32> {
    let retcode;
    let mut buffer = vec![0u8; 4];

    unsafe {
        retcode = __veracruz_hcall_previous_result_size(buffer.as_mut_ptr() as *mut u8);
    };

    lift(retcode, LittleEndian::read_u32(&buffer)).unwrap()
}

/// Reads the previous result, returned Option<Vec<u8>>.
/// The program is assumed to understand how to parse the array of bytes, wrapped in Some(-)
/// returned into something more meaningful, e.g. by fixing an assumed encoding
/// between data source providers and the program owner.
pub fn read_previous_result() -> HCallReturnCode<Option<Vec<u8>>> {
    previous_result_size().and_then(|size| {
        let mut buffer = vec![0u8; size as usize];
        let retcode;

        unsafe {
            retcode = __veracruz_hcall_read_previous_result(buffer.as_mut_ptr() as *mut u8, size)
        };

        let result: Option<Vec<u8>> = pinecone::from_bytes(&buffer).unwrap();

        lift(retcode, result).unwrap()
    })
}

/// Returns the number of stream sources that are available to the program.
///
/// The H-call does not fail.
pub fn stream_count() -> u32 {
    let retcode;
    let mut buffer = vec![0u8; 4];

    unsafe {
        retcode = __veracruz_hcall_stream_count(buffer.as_mut_ptr() as *mut u8);
    };

    assert_eq!(retcode, 0);

    LittleEndian::read_u32(&buffer)
}

/// Returns the size, in bytes, of the stream source indexed by `index`.
///
/// The H-call fails for only the following reasons:
///
/// 1. Fails if the `index` value is larger than the number of input sources
/// available to the program with `HCallReturnCode::ErrorDataSourceCount`.
pub fn stream_size(index: u32) -> HCallReturnCode<u32> {
    let retcode;
    let mut buffer = vec![0u8; 4];

    unsafe { retcode = __veracruz_hcall_stream_size(index, buffer.as_mut_ptr() as *mut u8) };

    lift(retcode, LittleEndian::read_u32(&buffer)).unwrap()
}

/// Reads a stream source, returned as a vector of `u8` values, indexed by `index`.
/// The program is assumed to understand how to parse the array of bytes
/// returned into something more meaningful, e.g. by fixing an assumed encoding
/// between data source providers and the program owner.
///
/// The H-call fails for only the following reasons:
///
/// 1. Fails if the `index` value is larger than the number of input sources
/// available to the program with `HCallReturnCode::ErrorDataSourceCount`.
pub fn read_stream(index: u32) -> HCallReturnCode<Vec<u8>> {
    stream_size(index).and_then(|size| {
        let mut buffer = vec![0u8; size as usize];
        let retcode;

        unsafe {
            retcode = __veracruz_hcall_read_stream(index, buffer.as_mut_ptr() as *mut u8, size)
        };

        lift(retcode, buffer).unwrap()
    })
}

/// Reads all streams, returned as a vector of vector of `u8` values.  The
/// program is assumed to understand how to parse the bytes returned into
/// something more meaningful, e.g. by fixing an assumed encoding between data
/// source providers and the program owner.
///
/// The H-call does not fail.
pub fn read_all_streams() -> Vec<Vec<u8>> {
    let inputs = stream_count();
    let mut buffer = Vec::new();

    for i in 0..inputs {
        let input = read_stream(i).expect("read_all_inputs: read_input failed.");
        buffer.push(input);
    }

    buffer
}
