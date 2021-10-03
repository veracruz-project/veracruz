//! Platform services
//!
//! A thin abstraction-layer over various platform services provided by individual
//! trusted execution environments and the Rust standard library (for
//! "freestanding-execution-engine").  These services are exposed by Veracruz to the WASM
//! program running in the TEE through a H-call.
//!
//! Services provided by this library:
//! - A random number source taken from a platform-specific trusted source of entropy
//!   (if within a TEE).  Note for `std` targets the random source is assumed to be
//!   the random number generator of the host operating system.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![no_std]

use crate::result::Result;
use cfg_if::cfg_if;

pub mod result;

cfg_if! {
    if #[cfg(feature = "sgx")] {
        #[path="sgx_platform_services.rs"]
        mod imp;
    } else if #[cfg(feature = "tz")] {
        #[path="tz_platform_services.rs"]
        mod imp;
    } else if #[cfg(feature = "nitro")] {
        #[path="nitro_platform_services.rs"]
        mod imp;
    } else if #[cfg(feature = "icecap")] {
        #[path="icecap_platform_services.rs"]
        mod imp;
    } else if #[cfg(feature = "std")] {
        #[path="std_platform_services.rs"]
        mod imp;

    } else {
        compile_error!(
            "Unrecognised feature: platforms supported are SGX, TZ, Nitro, and std.");
    }
}

////////////////////////////////////////////////////////////////////////////////
// Platform services
////////////////////////////////////////////////////////////////////////////////

/// Fills a `buffer` with random bytes taken from a trusted entropy source.
///
/// Returns:
///     - `result::Result::Success` if the random number generation successfully
///       completed.  In which case, `buffer` is correctly filled with random
///       bytes to completion.
///     - `result::Result::Unavailable` if a trusted source of entropy is not
///       available on this platform.  In which case, the contents of `buffer`
///       can be trusted not to have been modified by this function.
///     - `result::Result::UnknownError` if a runtime error occurred during
///       generation of the random numbers.  In which case, the contents of
///       `buffer` are undefined.
pub fn getrandom(buffer: &mut [u8]) -> result::Result<()> {
    if buffer.is_empty() {
        return Result::Success(());
    } else {
        imp::platform_getrandom(buffer)
    }
}

/// Gets resolution from the specified clock.
///
/// Returns:
///     - `result::Result::Success`, embedding the clock resolution in
///       nanoseconds, if the operation successfully completed.
///     - `result::Result::Unavailable` if the specified clock is not available
///       on this platform.
///     - `result::Result::UnknownError` if a runtime error occurred.
#[inline]
pub fn getclockres(clock_id: u8) -> result::Result<u64> {
    imp::platform_getclockres(clock_id)
}

/// Gets time from the specified clock.
///
/// Returns:
///     - `result::Result::Success`, embedding the clock time in
///       nanoseconds, if the operation successfully completed.
///     - `result::Result::Unavailable` if the specified clock is not available
///       on this platform.
///     - `result::Result::UnknownError` if a runtime error occurred.
#[inline]
pub fn getclocktime(clock_id: u8) -> result::Result<u64> {
    imp::platform_getclocktime(clock_id)
}
