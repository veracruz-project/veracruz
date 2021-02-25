//! Protocol operation-codes for the Runtime Manager
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[derive(Debug)]
pub enum RuntimeManagerOpcode {
    Initialize,
    GetEnclaveCertSize,
    GetEnclaveCert,
    GetEnclaveNameSize,
    GetEnclaveName,
    NewTLSSession,
    CloseTLSSession,
    GetTLSDataNeeded,
    SendTLSData,
    GetTLSData,
    GetPSAAttestationToken,
    ResetEnclave,
}

impl RuntimeManagerOpcode {
    pub fn from_u32(value: u32) -> Result<RuntimeManagerOpcode, String> {
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
                "veracruz_utils::RuntimeManagerOpcode::from_u32 failed to convert opcode:{:}",
                value
            )),
        }
    }
}

pub const MC_UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/runtime-manager-uuid.txt"));
