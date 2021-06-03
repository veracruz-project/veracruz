//! Protocol operation-codes for the the TrustZone root enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::{convert::TryFrom, string::String};

/// A Rust constant reflecting the value contained in the
/// `trustzone-root-enclave-uuid` text file, which is generated during
/// Veracruz's build process, and which represents the unique ID of the
/// TrustZone root enclave application.
pub const TRUSTZONE_ROOT_ENCLAVE_UUID: &str =
    &include_str!(concat!(env!("OUT_DIR"), "/trustzone-root-enclave-uuid.txt"));

/// Opcodes, or messages, that are passed to the TrustZone root enclave and
/// interpreted.
#[derive(Debug)]
pub enum TrustZoneRootEnclaveOpcode {
    /// A message requesting the length of the firmware version.
    GetFirmwareVersionLen,
    /// A message requesting the firmware version.
    GetFirmwareVersion,
    /// A message requesting native attestation.
    NativeAttestation,
    /// A message requesting proxy attestation.
    ProxyAttestation,
    /// Start the local attestation process by requesting a challenge value from
    /// the root enclave
    StartLocalAttestation,
    /// A message containing the certificate chain for the Root enclave
    CertificateChain,
    /// A message requesting that a "hack" (due to us not implementing
    /// attestation for Arm TrustZone, yet) is performed.
    SetRuntimeManagerHashHack,
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations.
////////////////////////////////////////////////////////////////////////////////

impl TryFrom<u32> for TrustZoneRootEnclaveOpcode {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TrustZoneRootEnclaveOpcode::GetFirmwareVersionLen),
            1 => Ok(TrustZoneRootEnclaveOpcode::GetFirmwareVersion),
            2 => Ok(TrustZoneRootEnclaveOpcode::NativeAttestation),
            3 => Ok(TrustZoneRootEnclaveOpcode::ProxyAttestation),
            4 => Ok(TrustZoneRootEnclaveOpcode::StartLocalAttestation),
            5 => Ok(TrustZoneRootEnclaveOpcode::CertificateChain),
            6 => Ok(TrustZoneRootEnclaveOpcode::SetRuntimeManagerHashHack),
            _ => Err(format!(
                "TrustZoneRootEnclaveOpcode:from_u32: Unknown value: {}",
                value
            )),
        }
    }
}
