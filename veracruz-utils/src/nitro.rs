use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum NitroStatus {
    Success,
    Fail,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ChiapasMessage {
    Status(NitroStatus),
    FetchFirmwareVersion,
    FirmwareVersion(String),
    SetMexicoCityHashHack(Vec<u8>), // hash
    NativeAttestation(Vec<u8>, i32), // challenge, device_id
    TokenData(Vec<u8>, Vec<u8>), // token, public_key
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MCMessage {
    Status(NitroStatus), // status
    Initialize(String), // policy_json
    GetEnclaveCert,
    EnclaveCert(Vec<u8>), // cert
    GetEnclaveName,
    EnclaveName(String), // enclave_name
    GetPSAAttestationToken(Vec<u8>), //challenge
    PSAAttestationToken(Vec<u8>, Vec<u8>, i32), // token, public_key, device_id
}