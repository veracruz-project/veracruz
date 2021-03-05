//! Protocol operation-codes for the SgxRootEnclave
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
pub enum SgxRootEnclaveOpcode {
    GetFirmwareVersionLen,
    GetFirmwareVersion,
    NativeAttestation,
    ProxyAttestation,
    SetMexicoCityHashHack,
}

impl SgxRootEnclaveOpcode {
    pub fn from_u32(value: u32) -> Result<SgxRootEnclaveOpcode, String> {
        match value {
            0 => Ok(SgxRootEnclaveOpcode::GetFirmwareVersionLen),
            1 => Ok(SgxRootEnclaveOpcode::GetFirmwareVersion),
            2 => Ok(SgxRootEnclaveOpcode::NativeAttestation),
            3 => Ok(SgxRootEnclaveOpcode::ProxyAttestation),
            4 => Ok(SgxRootEnclaveOpcode::SetMexicoCityHashHack),
            _ => Err(format!("SgxRootEnclaveOpcode:from_u32: Unknown value: {}", value)),
        }
    }
}

pub const SGX_ROOT_ENCLAVE_UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/sgx-root-enclave-uuid.txt"));
