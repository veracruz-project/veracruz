//! Types and definitions relating to the Veracruz global policy.
//!
//! The global policy captures important information about a Veracruz
//! computation that principals need to audit before they enroll themselves in a
//! computation.  This includes:
//!
//! - The identities and roles of every principals in the computation,
//! - Important URLs, both for the Veracruz bridge server on the untrusted
//!   host's machine and the Veracruz proxy attestation service,
//! - Permissible ciphersuites for TLS connections between clients and the
//!   trusted Veracruz runtime, as well as the hashes of the expected program
//!   and of the trusted Veracruz runtime itself,
//! - The expiry date (moment in time) of the self-signed certificate issued by
//!   the enclave during a pre-computation bootstrapping process,
//! - The execution strategy that will be used by the trusted Veracruz runtime
//!   to execute the WASM binary, as well as a debug configuration flag which
//!   allows the WASM binary to write data to `stdout` on the untrusted host's
//!   machine,
//! - The order in which data inputs provisioned into the enclave will be placed
//!   which is important for the program provider to understand in order to
//!   write software for Veracruz.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "std")]
use error::PlatformError;
#[cfg(feature = "std")]
use std::{fmt, str::FromStr};

/// Error types related to the handling of policies.
pub mod error;
/// Expiry timepoints for policies and their subcomponents.
pub mod expiry;
/// Parsers for turning strings into useful policy-related types.
pub mod parsers;
/// Pipelines of programs, and parsing their textual representation.
pub mod pipeline;
/// Types for working with policies themselves.
pub mod policy;
/// Principals, and their roles.
pub mod principal;

////////////////////////////////////////////////////////////////////////////
// Standard stream file paths.
////////////////////////////////////////////////////////////////////////////

/// Canonical file path for the stdin stream.
pub const CANONICAL_STDIN_FILE_PATH: &str = "stdin";
/// Canonical file path for the stdout stream.
pub const CANONICAL_STDOUT_FILE_PATH: &str = "stdout";
/// Canonical file path for the stderr stream.
pub const CANONICAL_STDERR_FILE_PATH: &str = "stderr";

////////////////////////////////////////////////////////////////////////////
// Platforms supported by Veracruz.
////////////////////////////////////////////////////////////////////////////

/// A type capturing the platform the enclave is running on.
#[derive(Debug)]
pub enum Platform {
    /// The enclave is running as a Linux process, either unprotected or as part of a
    /// protected Virtual Machine-like enclaving mechanism.
    Linux,
    /// The enclave is running under AWS Nitro enclaves.
    Nitro,
    /// The mock platform for unit testing (client unit tests, at the moment).
    Mock,
}

#[cfg(feature = "std")]
impl FromStr for Platform {
    type Err = PlatformError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "nitro" => Ok(Platform::Nitro),
            "linux" => Ok(Platform::Linux),
            _ => Err(PlatformError::InvalidPlatform(String::from(s))),
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Platform::Linux => write!(f, "linux"),
            Platform::Nitro => write!(f, "nitro"),
            Platform::Mock => write!(f, "mock"),
        }
    }
}
