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

#[cfg(feature = "linux")]
use bincode::Error as BincodeError;
use err_derive::Error;
#[cfg(feature = "linux")]
use std::io::Error as IOError;

////////////////////////////////////////////////////////////////////////////////
// Socket-related error types.
////////////////////////////////////////////////////////////////////////////////

/// a enumerated type for Veracruz-specific io errors
#[derive(Debug, Error)]
pub enum SocketError {
    /// A Bincode-related (de)serialization error occurred.
    #[cfg(feature = "linux")]
    #[error(
        display = "SocketError: a Bincode serialization error occurred: {:?}",
        _0
    )]
    BincodeError(BincodeError),
    /// An IO error occurred when writing to e.g. an FD.
    #[cfg(feature = "linux")]
    #[error(display = "SocketError: an IO error occurred: {:?}.", _0)]
    IOError(IOError),
    /// An error was returned by the Unix libraries.
    #[cfg(feature = "nitro")]
    #[error(display = "SocketError: a Unix error occurred: {:?}", _0)]
    NixError(#[error(source)] nix::Error),
}
