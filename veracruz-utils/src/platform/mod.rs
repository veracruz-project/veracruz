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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "linux")]
pub mod linux;
#[cfg(feature = "nitro")]
pub mod nitro;
#[cfg(feature = "tz")]
pub mod tz;
#[cfg(any(feature = "linux", feature = "nitro"))]
pub mod vm;

/// A type capturing the platform the enclave is running on.
pub enum Platform {
    /// The enclave is running as a Linux process, either unprotected or as part of a
    /// protected Virtual Machine-like enclaving mechanism.
    Linux,
    /// The enclave is running under Intel SGX.
    SGX,
    /// The enclave is running under Arm TrustZone.
    TrustZone,
    /// The enclave is running under AWS Nitro enclaves.
    Nitro,
    /// The mock platform for unit testing (client unit tests, at the moment).
    Mock,
}
