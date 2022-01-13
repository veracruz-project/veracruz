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


// read hardware registers for freq and time info
#[allow(deprecated)]
#[inline(never)]
fn read_cntfrq_el0() -> u32 {
    unsafe {
        let mut r: u32;
        llvm_asm!("mrs $0, cntfrq_el0" : "=r"(r));
        r
    }
}

#[allow(deprecated)]
#[inline(never)]
fn read_cntvct_el0() -> u64 {
    unsafe {
        let mut r: u64;
        llvm_asm!("mrs $0, cntvct_el0" : "=r"(r));
        r
    }
}

/// Returns the clock resolution in nanoseconds.
pub fn platform_getclockres(_clock_id: u8) -> Result<u64> {
    Result::Success(1)
}

/// Returns the clock time in nanoseconds.
pub fn platform_getclocktime(_clock_id: u8) -> Result<u64> {
    let freq = read_cntfrq_el0() as u64;
    let t = read_cntvct_el0();

    // returning time in nanoseconds
    Result::Success(1_000_000_000*t / freq)
}

