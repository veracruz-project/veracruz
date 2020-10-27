//! Arm TrustZone/OP-TEE-specific platform services
//!
//! Implements the `getrandom` platform service using a trusted entropy source
//! provided by OP-TEE.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::result;

use optee_utee::{Random};

/// Fills a buffer, `buffer`, with random bytes sampled from the thread-local
/// random number source.  Uses the Optee trusted RTS library from the Rust TZ
/// SDK to implement this.
pub fn platform_getrandom(buffer: &mut [u8]) -> result::Result {
    Random::generate(buffer);
    result::Result::Success
}
