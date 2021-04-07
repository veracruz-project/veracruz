//! Protocol operation-codes for the Veracruz runtime manager.
//!
//! Note that these are specific to the Arm TrustZone platform.
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
/// `runtime-manager-uuid` text file, which is generated during
/// Veracruz's build process, and which represents the unique ID of the
/// TrustZone runtime manager application.
pub const RUNTIME_MANAGER_UUID: &str =
    &include_str!(concat!(env!("OUT_DIR"), "/runtime-manager-uuid.txt"));

/// Opcodes, or messages, that are passed to the TrustZone runtime manager
/// application and interpreted.
#[derive(Debug)]
pub enum RuntimeManagerOpcode {
    /// A message requesting that the runtime manager is initialized.
    Initialize,
    /// A message requesting the size of the enclave's certificate.
    GetEnclaveCertSize,
    /// A message requesting the enclave's certificate.
    GetEnclaveCert,
    /// A message requesting the size of the enclave's name.
    GetEnclaveNameSize,
    /// A message requesting the enclave's name.
    GetEnclaveName,
    /// A message requesting that a new TLS session be initiated.
    NewTLSSession,
    /// A message requesting that an existing TLS session be torn down.
    CloseTLSSession,
    /// A message used to check whether further data is needed via TLS.
    GetTLSDataNeeded,
    /// A message used to indicate that data is being sent over TLS.
    SendTLSData,
    /// A message requesting TLS data.
    GetTLSData,
    /// A message requesting a PSA attestation token, for use during the
    /// Veracruz attestation process, is returned from the runtime manager.
    GetPSAAttestationToken,
    /// A message requesting that the runtime manager enclave be reset.
    ResetEnclave,
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations.
////////////////////////////////////////////////////////////////////////////////

impl TryFrom<u32> for RuntimeManagerOpcode {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RuntimeManagerOpcode::Initialize),
            1 => Ok(RuntimeManagerOpcode::GetEnclaveCertSize),
            2 => Ok(RuntimeManagerOpcode::GetEnclaveCert),
            3 => Ok(RuntimeManagerOpcode::GetEnclaveNameSize),
            4 => Ok(RuntimeManagerOpcode::GetEnclaveName),
            5 => Ok(RuntimeManagerOpcode::NewTLSSession),
            6 => Ok(RuntimeManagerOpcode::CloseTLSSession),
            7 => Ok(RuntimeManagerOpcode::GetTLSDataNeeded),
            8 => Ok(RuntimeManagerOpcode::SendTLSData),
            9 => Ok(RuntimeManagerOpcode::GetTLSData),
            10 => Ok(RuntimeManagerOpcode::GetPSAAttestationToken),
            11 => Ok(RuntimeManagerOpcode::ResetEnclave),
            _ => Err(format!(
                "RuntimeManagerOpcode could not be converted from: {}",
                value
            )),
        }
    }
}
