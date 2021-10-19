//! Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod veracruz_server;
pub use self::veracruz_server::*;

pub mod server;
pub use self::server::*;

#[cfg(feature = "tz")]
pub mod veracruz_server_tz;
#[cfg(feature = "tz")]
pub use self::veracruz_server_tz::veracruz_server_tz::*;

#[cfg(feature = "sgx")]
pub mod veracruz_server_sgx;
#[cfg(feature = "sgx")]
pub use self::veracruz_server_sgx::veracruz_server_sgx::*;

#[cfg(feature = "nitro")]
pub mod veracruz_server_nitro;
#[cfg(feature = "nitro")]
pub use self::veracruz_server_nitro::veracruz_server_nitro::*;

#[cfg(feature = "icecap")]
mod veracruz_server_icecap;
#[cfg(feature = "icecap")]
pub use self::veracruz_server_icecap::*;
