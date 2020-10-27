//! Sinaloa
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod sinaloa;
pub use self::sinaloa::*;

pub mod server;
pub use self::server::*;

#[cfg(feature = "tz")]
pub mod sinaloa_tz;
#[cfg(feature = "tz")]
pub use self::sinaloa_tz::sinaloa_tz::*;

#[cfg(feature = "sgx")]
pub mod sinaloa_sgx;
#[cfg(feature = "sgx")]
pub use self::sinaloa_sgx::sinaloa_sgx::*;
