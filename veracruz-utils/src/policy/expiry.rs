//! Expiry timepoints
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use serde::{Deserialize, Serialize};
use super::error::PolicyError;

////////////////////////////////////////////////////////////////////////////////
// Expiry timepoints.
////////////////////////////////////////////////////////////////////////////////

/// A year-month-day-minute ordinal timepoint, used to denote the moment when a
/// certificate will expire.
///
/// Semantics of fields follows ISO-8601.
///
/// Note that we do not validate certificate expiry timepoints from within the
/// enclave, as there is no way for us to obtain a reliable time, other than
/// checking that the fields are not "obviously" out of range for a timepoint
/// (e.g. having a `month` field of `60`).  Instead, this validation is left as
/// the responsibility of the clients.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Timepoint {
    /// Year of expiry.
    year: u32,
    /// Month of expiry.
    month: u8,
    /// Day of expiry.
    day: u8,
    /// Hour of expiry.
    hour: u8,
    /// Minute of expiry.
    minute: u8,
}

impl Timepoint {
    /// Constructs a new point of expiry from a year, month, day, hour, and
    /// minute.
    ///
    /// Fails if the fields do not conform with the formatting expectations of
    /// ISO-8601.
    pub fn new<T,U>(
        year: T,
        month: U,
        day: U,
        hour: U,
        minute: U,
    ) -> Result<Self, PolicyError>
    where
        T: Into<u32>,
        U: Into<u8>,
    {
        let month = month.into();
        let day = day.into();
        let hour = hour.into();
        let minute = minute.into();

        if minute > 59 {
            return Err(PolicyError::CertificateFormatError(format!(
                "invalid expiry minute {}",
                minute
            )));
        }

        if hour > 23 {
            return Err(PolicyError::CertificateFormatError(format!(
                "invalid expiry hour {}",
                hour
            )));
        }

        if day > 31 {
            return Err(PolicyError::CertificateFormatError(format!(
                "invalid expiry day {}",
                day
            )));
        }

        if month > 12 {
            return Err(PolicyError::CertificateFormatError(format!(
                "invalid expiry month {}",
                month
            )));
        }

        Ok(Self {
            year: year.into(),
            month,
            day,
            hour,
            minute,
        })
    }

    /// Returns the year of expiry.
    #[inline]
    pub fn year(&self) -> &u32 {
        &self.year
    }

    /// Returns the month of expiry.
    #[inline]
    pub fn month(&self) -> &u8 {
        &self.month
    }

    /// Returns the day of expiry.
    #[inline]
    pub fn day(&self) -> &u8 {
        &self.day
    }

    /// Returns the hour of expiry.
    #[inline]
    pub fn hour(&self) -> &u8 {
        &self.hour
    }

    /// Returns the minute of expiry.
    #[inline]
    pub fn minute(&self) -> &u8 {
        &self.minute
    }

    /// Returns the expiry moment, decoded into a tuple form of year, month,
    /// day, hour, minute, second.
    ///
    /// NB: note that the second field is always zero.
    #[inline]
    pub fn as_tuple(&self) -> (&u32, &u8, &u8, &u8, &u8, &u8) {
        (
            self.year(),
            self.month(),
            self.day(),
            self.hour(),
            self.minute(),
            &0,
        )
    }
}
