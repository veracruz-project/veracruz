//! Protocol operation-codes for Jalisco
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
pub enum JaliscoOpcode {
    GetFirmwareVersionLen,
    GetFirmwareVersion,
    NativeAttestation,
    ProxyAttestation,
    SetMexicoCityHashHack,
}

impl JaliscoOpcode {
    pub fn from_u32(value: u32) -> Result<JaliscoOpcode, String> {
        match value {
            0 => Ok(JaliscoOpcode::GetFirmwareVersionLen),
            1 => Ok(JaliscoOpcode::GetFirmwareVersion),
            2 => Ok(JaliscoOpcode::NativeAttestation),
            3 => Ok(JaliscoOpcode::ProxyAttestation),
            4 => Ok(JaliscoOpcode::SetMexicoCityHashHack),
            _ => Err(format!("JalsicoOpcode:from_u32: Unknown value: {}", value)),
        }
    }
}

pub const JALISCO_UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/jalisco_uuid.txt"));
