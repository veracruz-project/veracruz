//! Return codes for the Veracruz entry point
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use core::convert::TryFrom;
use core::fmt::{Display, Error, Formatter};

////////////////////////////////////////////////////////////////////////////////////////////////////
// Error codes.
////////////////////////////////////////////////////////////////////////////////////////////////////

/// Return codes returned from the Veracruz entry point, signalling to the Veracruz runtime whether
/// the computation was successful, or not.  (Strictly speaking, the entry point is assumed to
/// return a `Result<(), i32>` value,
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorCode {
    /// Generic, or underspecified, failure
    Generic,
    /// Failure related to the number of data sources, e.g. an invalid index
    DataSourceCount,
    /// Failure related to the size of data sources, e.g. a buffer size issue
    DataSourceSize,
    /// Failure related to parameters passed to a function, e.g. passing a
    /// negative value where an unsigned value is expected, or similar
    BadInput,
    /// An internal invariant was violated (i.e. we are morally `panicking').
    InvariantFailed,
    /// The required functionality is not yet implemented.
    NotImplemented,
    /// The required platform service is not available on this platform.
    ServiceUnavailable,
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Trait implementations.
////////////////////////////////////////////////////////////////////////////////////////////////////

/// Potentially-failing conversion from `i32` values.
impl TryFrom<i32> for ErrorCode {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        if value == -1 {
            Ok(ErrorCode::Generic)
        } else if value == -2 {
            Ok(ErrorCode::DataSourceCount)
        } else if value == -3 {
            Ok(ErrorCode::DataSourceSize)
        } else if value == -4 {
            Ok(ErrorCode::BadInput)
        } else if value == -5 {
            Ok(ErrorCode::InvariantFailed)
        } else if value == -6 {
            Ok(ErrorCode::NotImplemented)
        } else if value == -7 {
            Ok(ErrorCode::ServiceUnavailable)
        } else {
            Err(())
        }
    }
}

/// Non-failing conversion to `i32` values.
impl Into<i32> for ErrorCode {
    fn into(self) -> i32 {
        match self {
            ErrorCode::Generic => -1,
            ErrorCode::DataSourceCount => -2,
            ErrorCode::DataSourceSize => -3,
            ErrorCode::BadInput => -4,
            ErrorCode::InvariantFailed => -5,
            ErrorCode::NotImplemented => -6,
            ErrorCode::ServiceUnavailable => -7,
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            ErrorCode::Generic => write!(f, "Generic"),
            ErrorCode::DataSourceCount => write!(f, "DataSourceCount"),
            ErrorCode::DataSourceSize => write!(f, "DataSourceSize"),
            ErrorCode::BadInput => write!(f, "BadInput"),
            ErrorCode::InvariantFailed => write!(f, "InvariantFailed"),
            ErrorCode::NotImplemented => write!(f, "NotImplemented"),
            ErrorCode::ServiceUnavailable => write!(f, "ServiceUnavailable"),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Entry point return type.
////////////////////////////////////////////////////////////////////////////////////////////////////

/// The type of the Veracruz entry point.  A computation is either successful,
/// in which case `Ok(())` is returned, or there is a failure, in which case
/// `Err(e)` for some encoding of an `ErrorCode` value `e`, is returned.
pub type Veracruz = Result<(), i32>;

/// Utility function signalling success.
#[inline]
pub fn success() -> Veracruz {
    Ok(())
}

/// Utility function signalling generic failure.
#[inline]
pub fn fail_generic<T>() -> Result<T, i32> {
    Err(ErrorCode::Generic.into())
}

/// Utility function signalling failure due to the number of inputs.
#[inline]
pub fn fail_data_source_count<T>() -> Result<T, i32> {
    Err(ErrorCode::DataSourceCount.into())
}

/// Utility function signalling failure due to the size of an input.
#[inline]
pub fn fail_data_source_size<T>() -> Result<T, i32> {
    Err(ErrorCode::DataSourceSize.into())
}

/// Utility function signalling failure due to a bad input.
#[inline]
pub fn fail_bad_input<T>() -> Result<T, i32> {
    Err(ErrorCode::BadInput.into())
}

/// Utility function signalling failure due to a platform service not being available.
#[inline]
pub fn fail_service_unavailable<T>() -> Result<T, i32> {
    Err(ErrorCode::ServiceUnavailable.into())
}

/// Utility function signalling failure due to an invariant failing.
#[inline]
pub fn fail_invariant_failed<T>() -> Result<T, i32> {
    Err(ErrorCode::InvariantFailed.into())
}

/// Utility function signalling failure due to functionality not being implemented.
#[inline]
pub fn fail_not_implemented<T>() -> Result<T, i32> {
    Err(ErrorCode::NotImplemented.into())
}
