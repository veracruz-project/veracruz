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

/// Fill `buffer` with random bytes.
///
/// Until IceCap provides randomness for realms, this is just a placeholder
// generator with a fixed seed and a period of 2**61.
pub fn platform_getrandom(buffer: &mut [u8]) -> Result<()> {
    for b in buffer {
        let state = RNG_STATE.fetch_add(1, Ordering::SeqCst);
        *b = state.to_ne_bytes()[(state & 0b111) as usize];
    }
    Result::Success(())
}

/// Returns the clock resolution in nanoseconds.
pub fn platform_getclockres(_clock_id: u8) -> Result<u64> {
    Result::Unavailable
}

/// Returns the clock time in nanoseconds.
pub fn platform_getclocktime(_clock_id: u8) -> Result<u64> {
    Result::Unavailable
}
