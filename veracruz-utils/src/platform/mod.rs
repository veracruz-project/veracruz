//! Platform-specific material.
//!
//! Material specific to a particular platform that Veracruz supports, and which
//! does not fit elsewhere.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "nitro")]
pub mod nitro;
#[cfg(feature = "tz")]
pub mod tz;
#[cfg(feature = "icecap")]
pub mod icecap;

/// A type capturing the platform the enclave is running on.
pub enum Platform {
    /// The enclave is running under Intel SGX.
    SGX,
    /// The enclave is running under Arm TrustZone.
    TrustZone,
    /// The enclave is running under AWS Nitro enclaves.
    Nitro,
    /// The enclave is running under IceCap.
    IceCap,
    /// The mock platform for unit testing (client unit tests, at the moment).
    Mock,
}
