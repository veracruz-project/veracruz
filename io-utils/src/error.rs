//! IO-related errors
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use err_derive::Error;

////////////////////////////////////////////////////////////////////////////////
// Socket-related error types.
////////////////////////////////////////////////////////////////////////////////

/// a enumerated type for Veracruz-specific io errors
#[derive(Debug, Error)]
pub enum SocketError {
    /// An error was returned by nix
    #[error(display = "SocketError: a Unix error occurred: {:?}", _0)]
    NixError(#[error(source)] nix::Error),
}
