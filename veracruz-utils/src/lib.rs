//! The Veracruz utility library
//!
//! Material that doesn't fit anywhere else, or is common across many modules.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![cfg_attr(feature = "sgx", no_std)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

pub mod policy;
pub use crate::policy::*;

#[cfg(feature = "tz")]
pub mod mexico_city_opcode;
#[cfg(feature = "tz")]
pub use crate::mexico_city_opcode::*;

#[cfg(feature = "tz")]
pub mod jalisco_opcode;
#[cfg(feature = "tz")]
pub use crate::jalisco_opcode::*;

#[cfg(feature = "nitro")]
pub mod nitro;
#[cfg(feature = "nitro")]
pub use crate::nitro::*;

#[cfg(feature = "nitro")]
pub mod vsocket;
#[cfg(feature = "nitro")]
pub use self::vsocket::*;
