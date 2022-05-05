//! AWS Nitro enclaves specific platform services
//!
//! Implements the `getrandom` service using a trusted entropy source provided
//! by the AWS Nitro Enclave environment.
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
use nsm_api;
use nsm_lib;

/// Fills a buffer, `buffer`, with random bytes sampled from the thread-local
/// random number source.  Uses the AWS Nitro RNG
pub fn platform_getrandom(buffer: &mut [u8]) -> result::Result<()> {
    let nsm_fd = nsm_lib::nsm_lib_init();
    if nsm_fd < 0 {
        return result::Result::UnknownError;
    }
    let mut buffer_len = buffer.len();

    let status = unsafe { nsm_lib::nsm_get_random(nsm_fd, buffer.as_mut_ptr(), &mut buffer_len) };
    return match status {
        nsm_api::api::ErrorCode::Success => result::Result::Success(()),
        _ => result::Result::UnknownError,
    };
}

/// Returns the clock resolution in nanoseconds.
pub fn platform_getclockres(clock_id: u8) -> result::Result<u64> {
    let clock_id = time::ClockId::from_raw(clock_id.into());
    let timespec = match time::clock_getres(clock_id) {
        Ok(t) => t,
        Err(errno) => {
            if let nix::Error::Sys(e) = errno {
                if e == Errno::EINVAL {
                    return result::Result::Unavailable
                }
            }
            return result::Result::UnknownError
        },
    };
    result::Result::Success(timespec.num_nanoseconds() as u64)
}

/// Returns the clock time in nanoseconds.
pub fn platform_getclocktime(clock_id: u8) -> result::Result<u64> {
    let clock_id = time::ClockId::from_raw(clock_id.into());
    let timespec = match time::clock_gettime(clock_id) {
        Ok(t) => t,
        Err(errno) => {
            if let nix::Error::Sys(e) = errno {
                if e == Errno::EINVAL {
                    return result::Result::Unavailable
                }
            }
            return result::Result::UnknownError
        },
    };
    result::Result::Success(timespec.num_nanoseconds() as u64)
}
