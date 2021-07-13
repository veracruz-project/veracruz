//! Intel SGX-specific platform services
//!
//! Implements the `getrandom` service using a trusted entropy source taken from
//! the SGX RTS.
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

use sgx_trts::trts;

/// Fills a buffer, `buffer`, with random bytes sampled from the thread-local
/// random number source.  Uses the SGX trusted RTS library from the Rust SGX
/// SDK to implement this.
pub fn platform_getrandom(buffer: &mut [u8]) -> result::Result {
    if let Ok(_) = trts::rsgx_read_rand(buffer) {
        return result::Result::Success;
    }
    result::Result::UnknownError
}
