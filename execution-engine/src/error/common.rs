//! Common error handling code for all Chihuahua execution engines.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::fmt::Formatter;
use std::{
    convert::TryFrom,
    fmt::{Display, Error},
    string::String,
};

////////////////////////////////////////////////////////////////////////////////
// H-call error codes.
////////////////////////////////////////////////////////////////////////////////

/// These are error codes that the host passes back to the Veracruz WASM program
/// when something goes wrong with a host-call.  These errors are assumed to be
/// recoverable by the WASM program, if it cares to, and are distinct from host
/// errors which are akin to kernel panics and are always fatal.
///
/// Note that both the host and any Veracruz program need to agree on how these
/// errors are encoded.
#[derive(Clone, Copy, Debug)]
pub enum VeracruzError {
    /// The H-call completed successfully.
    Success,
    /// Generic failure: no more-specific information about the cause of the
    /// error can be given.
    Generic,
    /// The H-call failed because an index was passed that exceeded the number
    /// of data sources.
    DataSourceCount,
    /// The H-call failed because it was passed a buffer whose size did not
    /// match the size of the data source.
    DataSourceSize,
    /// The H-call failed because it was passed bad inputs.
    BadInput,
    /// The H-call failed because an index was passed that exceeded the number
    /// of stream sources.
    StreamSourceCount,
    /// The H-call failed because it was passed a buffer whose size did not
    /// match the size of the stream source.
    StreamSourceSize,
    /// The H-call failed because it was passed bad streams.
    BadStream,
    /// The H-call failed because it was passed a buffer whose size did not
    /// match the size of the previous result.
    PreviousResultSize,
    /// An internal invariant was violated (i.e. we are morally "panicking").
    InvariantFailed,
    /// The H-call failed because a result had already previously been written.
    ResultAlreadyWritten,
    /// The H-call failed because the platform service backing it is not
    /// available on this platform.
    ServiceUnavailable,
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations.
////////////////////////////////////////////////////////////////////////////////

/// Pretty printing for `VeracruzError`.
impl Display for VeracruzError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            VeracruzError::Success => write!(f, "Success"),
            VeracruzError::Generic => write!(f, "Generic"),
            VeracruzError::DataSourceSize => write!(f, "DataSourceSize"),
            VeracruzError::DataSourceCount => write!(f, "DataSourceCount"),
            VeracruzError::BadInput => write!(f, "BadInput"),
            VeracruzError::InvariantFailed => write!(f, "InvariantFailed"),
            VeracruzError::ResultAlreadyWritten => write!(f, "ResultAlreadyWritten"),
            VeracruzError::ServiceUnavailable => write!(f, "ServiceUnavailable"),
            VeracruzError::StreamSourceSize => write!(f, "StreamSourceSize"),
            VeracruzError::StreamSourceCount => write!(f, "StreamSourceCount"),
            VeracruzError::BadStream => write!(f, "BadStream"),
            VeracruzError::PreviousResultSize => write!(f, "PreviousResultSize"),
        }
    }
}

/// Serializes a `VeracruzError` to an `i32` value.
///
/// The Veracruz host passes error codes back to the WASM value encoded as an
/// `i32` value.  These are deserialized by the WASM program.
impl From<VeracruzError> for i32 {
    fn from(error: VeracruzError) -> i32 {
        match error {
            VeracruzError::Success => 0,
            VeracruzError::Generic => -1,
            VeracruzError::DataSourceCount => -2,
            VeracruzError::DataSourceSize => -3,
            VeracruzError::BadInput => -4,
            VeracruzError::InvariantFailed => -5,
            VeracruzError::ResultAlreadyWritten => -6,
            VeracruzError::ServiceUnavailable => -7,
            VeracruzError::StreamSourceCount => -8,
            VeracruzError::StreamSourceSize => -9,
            VeracruzError::BadStream => -10,
            VeracruzError::PreviousResultSize => -11,
        }
    }
}

/// Deserializes a `VeracruzError` from an `i32` value.
impl TryFrom<i32> for VeracruzError {
    type Error = String;

    fn try_from(i: i32) -> Result<Self, Self::Error> {
        match i {
            0 => Ok(VeracruzError::Success),
            -1 => Ok(VeracruzError::Generic),
            -2 => Ok(VeracruzError::DataSourceCount),
            -3 => Ok(VeracruzError::DataSourceSize),
            -4 => Ok(VeracruzError::BadInput),
            -5 => Ok(VeracruzError::InvariantFailed),
            -6 => Ok(VeracruzError::ResultAlreadyWritten),
            -7 => Ok(VeracruzError::ServiceUnavailable),
            -8 => Ok(VeracruzError::StreamSourceCount),
            -9 => Ok(VeracruzError::StreamSourceSize),
            -10 => Ok(VeracruzError::BadStream),
            -11 => Ok(VeracruzError::PreviousResultSize),
            otherwise => Err(format!(
                "Error converting i32 value '{}' to VeracruzError value.",
                otherwise
            )),
        }
    }
}
