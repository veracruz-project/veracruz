//! Rust standard library-specific platform services
//!
//! Implements the `getrandom` platform service using the Rust `getrandom::getrandom()`
//! function.
//! Implements the `getclockres` and `getclocktime` platform services using
//! functions provided by `nix::time`.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::result;

use nix::{errno::Errno, sys::time::TimeValLike, time};

/// Fills a buffer, `buffer`, with random bytes sampled from the random number
/// source provided by the host operating system, as provided by `getrandom`.
pub fn platform_getrandom(buffer: &mut [u8]) -> result::Result<()> {
    if getrandom::getrandom(buffer).is_ok() {
        return result::Result::Success(());
    }
    result::Result::UnknownError
}

/// Returns the clock resolution in nanoseconds.
pub fn platform_getclockres(clock_id: u8) -> result::Result<u64> {
    let clock_id = time::ClockId::from_raw(clock_id.into());
    let timespec = match time::clock_getres(clock_id) {
        Ok(t) => t,
        Err(errno) => match errno {
            Errno::EINVAL => return result::Result::Unavailable,
            _ => return result::Result::UnknownError,
        },
    };
    result::Result::Success(timespec.num_nanoseconds() as u64)
}

/// Returns the clock time in nanoseconds.
pub fn platform_getclocktime(clock_id: u8) -> result::Result<u64> {
    let clock_id = time::ClockId::from_raw(clock_id.into());
    let timespec = match time::clock_gettime(clock_id) {
        Ok(t) => t,
        Err(errno) => match errno {
            Errno::EINVAL => return result::Result::Unavailable,
            _ => return result::Result::UnknownError,
        },
    };
    result::Result::Success(timespec.num_nanoseconds() as u64)
}
