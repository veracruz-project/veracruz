//! Rust standard library-specific platform services
//!
//! Implements the `getrandom` platform service using the Rust `getrandom::getrandom()`
//! function.
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

/// Fills a buffer, `buffer`, with random bytes sampled from the random number
/// source provided by the host operating system, as provided by `getrandom`.
///
/// This is for use with "freestanding-execution-engine".
pub fn platform_getrandom(buffer: &mut [u8]) -> result::Result {
    if let Ok(_) = getrandom::getrandom(buffer) {
        return result::Result::Success;
    }
    result::Result::UnknownError
}
