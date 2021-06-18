//! IceCap-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::{
    env,
    fs::{OpenOptions, File},
    io::{Read, Write},
    mem::size_of,
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    result,
    sync::Mutex,
    string::ToString,
    process::Command,
};
use err_derive::Error;
use bincode::{serialize, deserialize};
use veracruz_utils::{
    policy::policy::Policy,
    platform::icecap::message::{Request, Response, Header},
};
use crate::veracruz_server::{VeracruzServer, VeracruzServerError};

const ICECAP_HOST_COMMAND_ENV: &str = "VERACRUZ_ICECAP_HOST_COMMAND";
const RESOURCE_SERVER_ENDPOINT_ENV: &str = "VERACRUZ_RESOURCE_SERVER_ENDPOINT";
const REALM_ID_ENV: &str = "VERACRUZ_REALM_ID";
const REALM_SPEC_ENV: &str = "VERACRUZ_REALM_SPEC";
const REALM_ENDPOINT_ENV: &str = "VERACRUZ_REALM_ENDPOINT";

const DEFAULT_ICECAP_HOST_COMMAND: &str = "icecap-host";

type Result<T> = result::Result<T, VeracruzServerError>;

#[derive(Debug, Error)]
pub enum IceCapError {
    #[error(display = "IceCap: Realm channel error")]
    RealmChannelError,
    #[error(display = "IceCap: Unexpected response from runtime manager: {:?}", _0)]
    UnexpectedRuntimeManagerResponse(Response),
    #[error(display = "IceCap: Missing environment variable: {}", variable)]
    MissingEnvironmentVariable { variable: String },
    #[error(display = "IceCap: Invalid environment variable value: {}", variable)]
    InvalidEnvironemntVariableValue { variable: String },
}

struct Configuration {
    icecap_host_command: PathBuf,
    resource_server_endpoint: PathBuf,
    realm_id: usize,
    realm_spec: PathBuf,
    realm_endpoint: PathBuf,
}

impl Configuration {

    fn env_var(var: &str) -> Result<String> {
        env::var(var).map_err(|_| VeracruzServerError::IceCapError(IceCapError::MissingEnvironmentVariable { variable: var.to_string() }))
    }

    fn from_env() -> Result<Self> {
        Ok(Self {
            icecap_host_command: Self::env_var(ICECAP_HOST_COMMAND_ENV).map(PathBuf::from).unwrap_or(DEFAULT_ICECAP_HOST_COMMAND.into()),
            resource_server_endpoint: Self::env_var(RESOURCE_SERVER_ENDPOINT_ENV)?.into(),
            realm_id: Self::env_var(REALM_ID_ENV)?.parse::<usize>().map_err(|_|
                VeracruzServerError::IceCapError(IceCapError::InvalidEnvironemntVariableValue { variable: REALM_ID_ENV.to_string() })
            )?,
            realm_spec: Self::env_var(REALM_SPEC_ENV)?.into(),
            realm_endpoint: Self::env_var(REALM_ENDPOINT_ENV)?.into(),
        })
    }

    fn create_realm(&self) -> Result<()> {
        let status = Command::new(&self.icecap_host_command)
            .arg("create")
            .arg(format!("{}", self.realm_id))
            .arg(&self.realm_spec)
            .arg(&self.resource_server_endpoint)
            .status().unwrap();
        assert!(status.success());
        Ok(())
    }
    
    fn run_realm(&self) -> Result<()> {
        let status = Command::new(&self.icecap_host_command)
            .arg("hack-run")
            .arg(format!("{}", self.realm_id))
            .status().unwrap();
        assert!(status.success());
        Ok(())
    }
    
    fn destroy_realm(&self) -> Result<()> {
        let status = Command::new(&self.icecap_host_command)
            .arg("destroy")
            .arg(format!("{}", self.realm_id))
            .status().unwrap();
        assert!(status.success());
        Ok(())
    }

}

pub struct VeracruzServerIceCap {
    configuration: Configuration,
    realm_handle: Mutex<File>,

    // HACK
    device_id: i32,
}

impl VeracruzServer for VeracruzServerIceCap {

    fn new(policy_json: &str) -> Result<Self> {

        let policy: Policy = Policy::from_json(policy_json)?;

        let device_id = hack::native_attestation(&policy.proxy_attestation_server_url())?;

        let configuration = Configuration::from_env()?;
        configuration.destroy_realm()?; // HACK
        configuration.create_realm()?;
        configuration.run_realm()?;
        let realm_handle = Mutex::new(
            OpenOptions::new().read(true).write(true).open(&configuration.realm_endpoint)
                .map_err(|_| VeracruzServerError::IceCapError(IceCapError::RealmChannelError))?
        );
        let server = Self {
            configuration,
            realm_handle,
            device_id,
        };
        match server.send(&Request::New { policy_json: policy_json.to_string() })? {
            Response::New => (),
            resp => return Err(VeracruzServerError::IceCapError(IceCapError::UnexpectedRuntimeManagerResponse(resp))),
        }
        Ok(server)
    }

    fn proxy_psa_attestation_get_token(
        &mut self,
        challenge: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>, i32)> {
        let enclave_cert = self.get_enclave_cert()?;
        let (token, device_public_key) = hack::proxy_attesation(&challenge, &enclave_cert)?;
        Ok((token, device_public_key, self.device_id))
    }

    fn plaintext_data(&mut self, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let parsed = transport_protocol::parse_runtime_manager_request(&data)?;

        if parsed.has_request_proxy_psa_attestation_token() {
            let rpat = parsed.get_request_proxy_psa_attestation_token();
            let challenge = transport_protocol::parse_request_proxy_psa_attestation_token(rpat);
            let (psa_attestation_token, pubkey, device_id) =
                self.proxy_psa_attestation_get_token(challenge)?;
            let serialized_pat = transport_protocol::serialize_proxy_psa_attestation_token(
                &psa_attestation_token,
                &pubkey,
                device_id,
            )?;
            Ok(Some(serialized_pat))
        } else {
            Err(VeracruzServerError::MissingFieldError(
                "plaintext_data proxy_psa_attestation_token",
            ))
        }
    }

    fn get_enclave_cert(&mut self) -> Result<Vec<u8>> {
       match self.send(&Request::GetEnclaveCert)? {
           Response::GetEnclaveCert(cert) => Ok(cert),
           resp => Err(VeracruzServerError::IceCapError(IceCapError::UnexpectedRuntimeManagerResponse(resp))),
       }
    }

    fn get_enclave_name(&mut self) -> Result<String> {
       match self.send(&Request::GetEnclaveName)? {
           Response::GetEnclaveName(name) => Ok(name),
           resp => Err(VeracruzServerError::IceCapError(IceCapError::UnexpectedRuntimeManagerResponse(resp))),
       }
    }

    fn new_tls_session(&mut self) -> Result<u32> {
       match self.send(&Request::NewTlsSession)? {
           Response::NewTlsSession(session_id) => Ok(session_id),
           resp => Err(VeracruzServerError::IceCapError(IceCapError::UnexpectedRuntimeManagerResponse(resp))),
       }
    }

    fn close_tls_session(&mut self, session_id: u32) -> Result<()> {
       match self.send(&Request::CloseTlsSession(session_id))? {
           Response::CloseTlsSession => Ok(()),
           resp => Err(VeracruzServerError::IceCapError(IceCapError::UnexpectedRuntimeManagerResponse(resp))),
       }
    }

    fn tls_data(&mut self, session_id: u32, input: Vec<u8>) -> Result<(bool, Option<Vec<Vec<u8>>>)> {
        match self.send(&Request::SendTlsData(session_id, input))? {
            Response::SendTlsData => (),
            resp => return Err(VeracruzServerError::IceCapError(IceCapError::UnexpectedRuntimeManagerResponse(resp))),
        }

        let mut acc = Vec::new();
        let active = loop {
            if !self.tls_data_needed(session_id)? {
                break true;
            }
            match self.send(&Request::GetTlsData(session_id))? {
                Response::GetTlsData(active, data) => {
                    acc.push(data);
                    if !active {
                        break false;
                    }
                }
                resp => return Err(VeracruzServerError::IceCapError(IceCapError::UnexpectedRuntimeManagerResponse(resp))),
            };
        };

        Ok((active, match acc.len() {
            0 => None,
            _ => Some(acc),
        }))
    }

    fn close(&mut self) -> Result<bool> {
        self.configuration.destroy_realm()?;
        Ok(true)
    }
}

impl Drop for VeracruzServerIceCap {
    fn drop(&mut self) {
        if let Err(err) = self.close() {
            panic!("Veracruz server failed to close: {}", err)
        }
    }
}

impl VeracruzServerIceCap {

    fn send(&self, request: &Request) -> Result<Response> {
        let msg = serialize(request).unwrap();
        let header = (msg.len() as Header).to_le_bytes();
        let mut realm_handle = self.realm_handle.lock().unwrap();
        realm_handle.write(&header).unwrap();
        realm_handle.write(&msg).unwrap();
        let mut header_bytes = [0; size_of::<Header>()];
        realm_handle.read_exact(&mut header_bytes).unwrap();
        let header = u32::from_le_bytes(header_bytes);
        let mut resp_bytes = vec![0; header as usize];
        realm_handle.read_exact(&mut resp_bytes).unwrap();
        let resp = deserialize(&resp_bytes).unwrap();
        Ok(resp)
    }

    fn tls_data_needed(&self, session_id: u32) -> Result<bool> {
        match self.send(&Request::GetTlsDataNeeded(session_id))? {
            Response::GetTlsDataNeeded(needed) => Ok(needed),
            resp => Err(VeracruzServerError::IceCapError(IceCapError::UnexpectedRuntimeManagerResponse(resp))),
        }
    }

}

// HACK
mod hack {
    use once_cell::sync::OnceCell;
    use super::Result;

    const EXAMPLE_HASH: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe,
        0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe,
    ];

    const EXAMPLE_PRIVATE_KEY: [u8; 32] = [
        0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe,
        0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
        0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31,
        0xc1, 0xd4, 0xee, 0x1c, 0x05, 0x76, 0xa1, 0x44,
    ];

    const RUNTIME_MANAGER_HASH: &[u8] = &EXAMPLE_HASH;
    const ROOT_HASH: &[u8] = &EXAMPLE_HASH;

    const DEVICE_PRIVATE_KEY: &[u8] = &EXAMPLE_PRIVATE_KEY;
    const ROOT_PRIVATE_KEY: &[u8] = &EXAMPLE_PRIVATE_KEY;

    const FIRMWARE_VERSION: &str = "0.3.0";

    static DEVICE_ID: OnceCell<i32> = OnceCell::new();

    fn get_device_public_key() -> Vec<u8> {
        let device_private_key = &DEVICE_PRIVATE_KEY;
        let mut device_key_handle: u16 = 0;
        assert_eq!(0, unsafe {
            psa_attestation::psa_initial_attest_load_key(
                device_private_key.as_ptr(),
                device_private_key.len() as u64,
                &mut device_key_handle,
            )
        });
        let mut device_public_key = std::vec::Vec::with_capacity(128);
        let mut device_public_key_size: u64 = 0;
        assert_eq!(0, unsafe {
            psa_attestation::t_cose_sign1_get_verification_pubkey(
                device_key_handle,
                device_public_key.as_mut_ptr() as *mut u8,
                device_public_key.capacity() as u64,
                &mut device_public_key_size as *mut u64,
            )
        });
        unsafe {
            device_public_key.set_len(device_public_key_size as usize)
        };
        device_public_key
    }

    pub(super) fn native_attestation(proxy_attestation_server_url: &str) -> Result<i32> {
        Ok(*DEVICE_ID.get_or_init(|| {
            native_attestation_once(proxy_attestation_server_url).unwrap() // HACK
        }))
    }

    fn native_attestation_once(proxy_attestation_server_url: &str) -> Result<i32> {
        let proxy_attestation_server_response = crate::send_proxy_attestation_server_start(proxy_attestation_server_url, "psa", FIRMWARE_VERSION)?;
        assert!(proxy_attestation_server_response.has_psa_attestation_init());
        let (challenge, device_id) = transport_protocol::parse_psa_attestation_init(
            proxy_attestation_server_response.get_psa_attestation_init(),
        )?;

        let root_hash = ROOT_HASH;

        let token = {
            let mut token: Vec<u8> = Vec::with_capacity(2048);
            let mut token_len: u64 = 0;
            let device_public_key_hash = ring::digest::digest(&ring::digest::SHA256, &get_device_public_key());
            let enclave_name = "ac40a0c".as_bytes(); // HACK
            assert_eq!(0, unsafe {
                psa_attestation::psa_initial_attest_get_token(
                    root_hash.as_ptr() as *const u8,
                    root_hash.len() as u64,
                    device_public_key_hash.as_ref().as_ptr() as *const u8,
                    device_public_key_hash.as_ref().len() as u64,
                    enclave_name.as_ptr() as *const u8,
                    enclave_name.len() as u64,
                    challenge.as_ptr() as *const u8,
                    challenge.len() as u64,
                    token.as_mut_ptr() as *mut u8,
                    2048,
                    &mut token_len as *mut u64,
                )
            });
            unsafe {
                token.set_len(token_len as usize)
            };
            token
        };

        let proxy_attestation_server_request = transport_protocol::serialize_native_psa_attestation_token(&token, device_id)?;
        let encoded_str = base64::encode(&proxy_attestation_server_request);
        let url = format!("{:}/PSA/AttestationToken", proxy_attestation_server_url);
        crate::post_buffer(&url, &encoded_str)?;

        Ok(device_id)
    }

    pub(super) fn proxy_attesation(challenge: &[u8], enclave_cert: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let enclave_hash = &RUNTIME_MANAGER_HASH;

        let token = {
            let mut token: Vec<u8> = Vec::with_capacity(2048);
            let mut token_len: u64 = 0;
            let enclave_cert_hash = ring::digest::digest(&ring::digest::SHA256, &enclave_cert);
            let enclave_name = "ac40a0c".as_bytes();
            assert_eq!(0, unsafe {
                psa_attestation::psa_initial_attest_get_token(
                    enclave_hash.as_ptr() as *const u8,
                    enclave_hash.len() as u64,
                    enclave_cert_hash.as_ref().as_ptr() as *const u8,
                    enclave_cert_hash.as_ref().len() as u64,
                    enclave_name.as_ptr() as *const u8,
                    enclave_name.len() as u64,
                    challenge.as_ptr() as *const u8,
                    challenge.len() as u64,
                    token.as_mut_ptr() as *mut u8,
                    2048,
                    &mut token_len as *mut u64,
                )
            });
            unsafe {
                token.set_len(token_len as usize)
            };
            token
        };

        Ok((token, get_device_public_key()))
    }
}
