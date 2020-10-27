//! Protocol operation-codes for Mexico City
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
pub enum MCOpcode {
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

impl MCOpcode {
    pub fn from_u32(value: u32) -> Result<MCOpcode, String> {
        match value {
            0 => Ok(MCOpcode::Initialize),
            1 => Ok(MCOpcode::GetEnclaveCertSize),
            2 => Ok(MCOpcode::GetEnclaveCert),
            3 => Ok(MCOpcode::GetEnclaveNameSize),
            4 => Ok(MCOpcode::GetEnclaveName),
            5 => Ok(MCOpcode::NewTLSSession),
            6 => Ok(MCOpcode::CloseTLSSession),
            7 => Ok(MCOpcode::GetTLSDataNeeded),
            8 => Ok(MCOpcode::SendTLSData),
            9 => Ok(MCOpcode::GetTLSData),
            10 => Ok(MCOpcode::GetPSAAttestationToken),
            11 => Ok(MCOpcode::ResetEnclave),
            _ => Err(format!(
                "veracruz_utils::MCOpcode::from_u32 failed to convert opcode:{:}",
                value
            )),
        }
    }
}

pub const MC_UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/mexico_city_uuid.txt"));
