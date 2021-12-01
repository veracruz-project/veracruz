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

#[cfg(feature = "nitro")]
pub mod veracruz_server_nitro;
#[cfg(feature = "nitro")]
pub use self::veracruz_server_nitro::veracruz_server_nitro::*;

#[cfg(feature = "icecap")]
mod veracruz_server_icecap;
#[cfg(feature = "icecap")]
pub use self::veracruz_server_icecap::*;
#[cfg(feature = "linux")]
pub mod veracruz_server_linux;
#[cfg(feature = "linux")]
pub use self::veracruz_server_linux::veracruz_server_linux::*;
