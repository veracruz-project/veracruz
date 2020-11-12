use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum NitroStatus {
    Success,
    Fail,
    Unimplemented,
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
    NewTLSSession,
    TLSSession(u32), // session_id
    CloseTLSSession(u32), // session_id
    GetTLSDataNeeded(u32), // session_id
    TLSDataNeeded(bool), // data_neeeded
    SendTLSData(u32, Vec<u8>), // session_id, tls_data,
    GetTLSData(u32), // session_id
    TLSData(Vec<u8>, bool), // TLS Data, alive_flag
    ResetEnclave,
}