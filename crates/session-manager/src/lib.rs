//! The session manager's library
//!
//! Code for sending and receiving data over a TLS-encrypted link, inside the
//! Veracruz runtime.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod session_context;
pub use self::session_context::*;
pub mod session;
pub use self::session::*;
pub mod error;
pub use self::error::SessionManagerError;
