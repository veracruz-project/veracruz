//! IceCap-specific platform services
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::Result;
use core::sync::atomic::{AtomicU64, Ordering};

static RNG_STATE: AtomicU64 = AtomicU64::new(0);

/// Fills a buffer, `buffer`, with random bytes sampled from the thread-local
/// random number source.
///
/// Not yet implemented in IceCap.
pub fn platform_getrandom(buffer: &mut [u8]) -> Result<()> {
    Result::Unavailable
}

/// Returns the clock resolution in nanoseconds.
///
/// Not yet implemented in IceCap.
pub fn platform_getclockres(_clock_id: u8) -> Result<u64> {
    Result::Unavailable
}

/// Returns the clock time in nanoseconds.
///
/// Not yet implemented in IceCap.
pub fn platform_getclocktime(_clock_id: u8) -> Result<u64> {
    Result::Unavailable
}
