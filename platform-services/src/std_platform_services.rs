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

use getrandom;
use nix::{
    time,
    sys::time::TimeValLike,
};

/// Fills a buffer, `buffer`, with random bytes sampled from the random number
/// source provided by the host operating system, as provided by `getrandom`.
pub fn platform_getrandom(buffer: &mut [u8]) -> result::Result<()> {
    if let Ok(_) = getrandom::getrandom(buffer) {
        return result::Result::Success(());
    }
    result::Result::UnknownError
}

/// Returns the clock resolution in nanoseconds.
pub fn platform_getclockres(clock_id: u8) -> result::Result<u64> {
    let clock_id = time::ClockId::from_raw(clock_id.into());
    let timespec = match time::clock_getres(clock_id) {
        Ok(t) => t,
        Err(_) => return result::Result::Unavailable,
    };

    // Catch overflow
    if timespec.tv_sec() == 0 {
        result::Result::UnknownError
    } else {
        result::Result::Success(timespec.num_nanoseconds() as u64)
    }
}

/// Returns the clock time in nanoseconds.
pub fn platform_getclocktime(clock_id: u8) -> result::Result<u64> {
    let clock_id = time::ClockId::from_raw(clock_id.into());
    let timespec = match time::clock_gettime(clock_id) {
        Ok(t) => t,
        Err(_) => return result::Result::Unavailable,
    };
    result::Result::Success(timespec.num_nanoseconds() as u64)
}
