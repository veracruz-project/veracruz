//! Shim layer
//!
//! A layer exposing platform services to external Rust dependencies and
//! handling FFI between Rust and C
//!
//! Services exposed:
//! - getrandom()
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::{getrandom, result::Result};

pub extern "C" fn veracruz_getrandom(buf: *mut u8, buflen: usize, _flags: usize) -> isize {
	let slice: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(buf, buflen) };
	match getrandom(slice) {
		Result::Success(_) => slice.len() as isize,
		_otherwise => -1
	}
}
