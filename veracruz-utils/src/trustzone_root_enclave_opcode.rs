//! Protocol operation-codes for the TrustZoneRootEnclave
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
pub enum TrustZoneRootEnclaveOpcode {
    GetFirmwareVersionLen,
    GetFirmwareVersion,
    NativeAttestation,
    ProxyAttestation,
    SetRuntimeManagerHashHack,
}

impl TrustZoneRootEnclaveOpcode {
    pub fn from_u32(value: u32) -> Result<TrustZoneRootEnclaveOpcode, String> {
        match value {
            0 => Ok(TrustZoneRootEnclaveOpcode::GetFirmwareVersionLen),
            1 => Ok(TrustZoneRootEnclaveOpcode::GetFirmwareVersion),
            2 => Ok(TrustZoneRootEnclaveOpcode::NativeAttestation),
            3 => Ok(TrustZoneRootEnclaveOpcode::ProxyAttestation),
            4 => Ok(TrustZoneRootEnclaveOpcode::SetRuntimeManagerHashHack),
            _ => Err(format!("TrustZoneRootEnclaveOpcode:from_u32: Unknown value: {}", value)),
        }
    }
}

pub const TRUSTZONE_ROOT_ENCLAVE_UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/trustzone-root-enclave-uuid.txt"));
