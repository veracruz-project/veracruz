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

use core::sync::atomic::{AtomicU64, Ordering};
use crate::Result;

// HACK
// Placeholder generator with a fixed seed and a period of 2**61

static STATE: AtomicU64 = AtomicU64::new(0);

pub fn platform_getrandom(buffer: &mut [u8]) -> Result {
    for b in buffer {
        let state = STATE.fetch_add(1, Ordering::SeqCst);
        *b = state.to_ne_bytes()[(state & 0b111) as usize];
    }
    Result::Success
}
