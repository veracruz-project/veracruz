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
    /// A message requesting a Certificate Signing Request (CSR) to be sent
    /// to the root enclave to be converted to a certificate
    GetCSR,
    /// A message signaling the engine to populate it's certificate chain
    /// with provided certificate data
    PopulateCertificates,
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
            1 => Ok(RuntimeManagerOpcode::NewTLSSession),
            2 => Ok(RuntimeManagerOpcode::CloseTLSSession),
            3 => Ok(RuntimeManagerOpcode::GetTLSDataNeeded),
            4 => Ok(RuntimeManagerOpcode::SendTLSData),
            5 => Ok(RuntimeManagerOpcode::GetTLSData),
            6 => Ok(RuntimeManagerOpcode::GetCSR),
            7 => Ok(RuntimeManagerOpcode::PopulateCertificates),
            8 => Ok(RuntimeManagerOpcode::ResetEnclave),
            _ => Err(format!(
                "RuntimeManagerOpcode could not be converted from: {}",
                value
            )),
        }
    }
}
