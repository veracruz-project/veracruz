//! IceCap-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::common::{VeracruzServer, VeracruzServerError};
use err_derive::Error;
use io_utils::http::{post_buffer, send_proxy_attestation_server_start};
use policy_utils::policy::Policy;
use signal_hook::{
    consts::SIGINT,
    iterator::{Handle, Signals},
};
use std::{
    convert::TryFrom,
    env,
    error::Error,
    fs,
    io::{self, Read, Write},
    mem::size_of,
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    string::ToString,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};
use tempfile::{self, TempDir};
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};

const VERACRUZ_ICECAP_LKVM_BIN_DEFAULT: &'static [&'static str] = &["/work/cca/platform/lkvm"];
const VERACRUZ_ICECAP_LKVM_FLAGS_DEFAULT: &'static [&'static str] = &[
    "run",
    "--realm",
    "--irqchip=gicv3",
    "--console=serial", 
    "--network",
    "mode=none",
    "--tty",
    "4,/tmp/veracruz.sock",
    "--no9p",
    "--ns-pool-size",
    "3M",
    "-c",
    "1",
    "-m",
    "512",
];
const VERACRUZ_ICECAP_LKVM_FIRMWARE_IMAGE_DEFAULT: &'static [&'static str] = &["-f", "/work/cca/platform/veracruz.bin"];
const VERACRUZ_ICECAP_LKVM_FIRMWARE_ADDRESS_DEFAULT: &'static [&'static str] = &["--firmware-address", "0x81191000"];

// TODO is this needed?
const FIRMWARE_VERSION: &str = "0.3.0";

/// Class of IceCap-specific errors.
#[derive(Debug, Error)]
pub enum IceCapError {
    #[error(display = "IceCap: Invalid environment variable value: {}", variable)]
    InvalidEnvironmentVariableValue { variable: String },
    #[error(display = "IceCap: Channel error: {}", _0)]
    ChannelError(io::Error),
    #[error(display = "IceCap: LKVM spawn error: {}", _0)]
    LkvmSpawnError(io::Error),
    #[error(display = "IceCap: Serialization error: {}", _0)]
    SerializationError(#[error(source)] bincode::Error),
    #[error(display = "IceCap: Unexpected response from runtime manager: {:?}", _0)]
    UnexpectedRuntimeManagerResponse(RuntimeManagerResponse),
}

/// IceCap implementation of 'VeracruzServer'
struct IceCapRealm {
    // NOTE the order of these fields matter due to drop ordering
    child: Arc<Mutex<Child>>,
    channel: UnixStream,
    #[allow(dead_code)]
    tempdir: TempDir,
}

impl IceCapRealm {
    fn spawn() -> Result<IceCapRealm, VeracruzServerError> {
        fn env_flags(var: &str, default: &[&str]) -> Result<Vec<String>, IceCapError> {
            match env::var(var) {
                Ok(var) => Ok(var.split_whitespace().map(|s| s.to_owned()).collect()),
                Err(env::VarError::NotPresent) => {
                    Ok(default.iter().map(|s| (*s).to_owned()).collect())
                }
                Err(_) => Err(IceCapError::InvalidEnvironmentVariableValue {
                    variable: var.to_owned(),
                }
                .into()),
            }
        }

        // Allow overriding these from environment variables
        let lkvm_bin = env_flags("VERACRUZ_ICECAP_LKVM_BIN", VERACRUZ_ICECAP_LKVM_BIN_DEFAULT)?;
        let lkvm_flags = env_flags("VERACRUZ_ICECAP_LKVM_FLAGS", VERACRUZ_ICECAP_LKVM_FLAGS_DEFAULT)?;
        let lkvm_firmware_flags = env_flags(
            "VERACRUZ_ICECAP_LKVM_FIRMWARE_IMAGE",
            VERACRUZ_ICECAP_LKVM_FIRMWARE_IMAGE_DEFAULT,
        )?;
        let lkvm_firmware_address_flags = env_flags(
            "VERACRUZ_ICECAP_LKVM_FIRMWARE_ADDRESS",
            VERACRUZ_ICECAP_LKVM_FIRMWARE_ADDRESS_DEFAULT,
        )?;

        // temporary directory for things
        let tempdir = tempfile::tempdir()?;

        // create a temporary socket for communication
        let channel_path = tempdir.path().join("/tmp/veracruz.sock");
        println!("vc-server: using unix socket: {:?}", channel_path);

        // startup qemu
        let child = Arc::new(Mutex::new(
            Command::new(&lkvm_bin[0])
                .args(&lkvm_bin[1..])
                .args(&lkvm_flags)
                .args(&lkvm_firmware_flags)
                .args(&lkvm_firmware_address_flags)
                .spawn()
                .map_err(IceCapError::LkvmSpawnError)?,
        ));
        // connect via socket
        let channel = loop {
            match UnixStream::connect(&channel_path) {
                Ok(channel) => {
                    break channel;
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                // NOTE I don't know why this one happens
                Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(err) => {
                    return Err(IceCapError::ChannelError(err).into());
                }
            };
        };

        Ok(IceCapRealm {
            child,
            channel,
            tempdir,
        })
    }

    fn communicate(
        &mut self,
        request: &RuntimeManagerRequest,
    ) -> Result<RuntimeManagerResponse, IceCapError> {
        // send request
        let raw_request = bincode::serialize(request)?;
        let raw_header = bincode::serialize(&u32::try_from(raw_request.len()).unwrap())?;
        self.channel
            .write_all(&raw_header)
            .map_err(IceCapError::ChannelError)?;
        self.channel
            .write_all(&raw_request)
            .map_err(IceCapError::ChannelError)?;

        // recv response
        let mut raw_header = [0; size_of::<u32>()];
        self.channel
            .read_exact(&mut raw_header)
            .map_err(IceCapError::ChannelError)?;
        let header = bincode::deserialize::<u32>(&raw_header)?;
        let mut raw_response = vec![0; usize::try_from(header).unwrap()];
        self.channel
            .read_exact(&mut raw_response)
            .map_err(IceCapError::ChannelError)?;
        let response = bincode::deserialize::<RuntimeManagerResponse>(&raw_response)?;

        Ok(response)
    }

    // NOTE close can report errors, but drop can still happen in weird cases
    fn shutdown(self) -> Result<(), IceCapError> {
        println!("vc-server: shutting down");
        self.child
            .lock()
            .unwrap()
            .kill()
            .map_err(|e| IceCapError::ChannelError(e))?;
        Ok(())
    }
}

pub struct VeracruzServerIceCapCCA(Option<IceCapRealm>);

impl VeracruzServerIceCapCCA {
    fn communicate(
        &mut self,
        request: &RuntimeManagerRequest,
    ) -> Result<RuntimeManagerResponse, VeracruzServerError> {
        let response = self
            .0
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?
            .communicate(request)?;
        Ok(response)
    }

    fn tls_data_needed(&mut self, session_id: u32) -> Result<bool, VeracruzServerError> {
        match self.communicate(&RuntimeManagerRequest::GetTlsDataNeeded(session_id))? {
            RuntimeManagerResponse::TlsDataNeeded(needed) => Ok(needed),
            resp => Err(IceCapError::UnexpectedRuntimeManagerResponse(resp).into()),
        }
    }
}

impl VeracruzServer for VeracruzServerIceCapCCA {
    fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
        let policy: Policy = Policy::from_json(policy_json)?;

        let mut self_ = Self(Some(IceCapRealm::spawn()?));

        let (device_id, challenge) = send_proxy_attestation_server_start(
            policy.proxy_attestation_server_url(),
            "psa",
            FIRMWARE_VERSION,
        )?;

        let (token, csr) =
            match self_.communicate(&RuntimeManagerRequest::Attestation(challenge, device_id))? {
                RuntimeManagerResponse::AttestationData(token, csr) => (token, csr),
                resp => {
                    return Err(VeracruzServerError::IceCapError(
                        IceCapError::UnexpectedRuntimeManagerResponse(resp),
                    ))
                }
            };

        let (root_cert, compute_cert) = {
            let req = transport_protocol::serialize_native_psa_attestation_token(
                &token, &csr, device_id,
            )?;
            let req = base64::encode(&req);
            let url = format!(
                "{:}/PSA/AttestationToken",
                policy.proxy_attestation_server_url()
            );
            let resp = post_buffer(&url, &req)?;
            let resp = base64::decode(&resp)?;
            let pasr = transport_protocol::parse_proxy_attestation_server_response(None, &resp)?;
            let cert_chain = pasr.get_cert_chain();
            let root_cert = cert_chain.get_root_cert();
            let compute_cert = cert_chain.get_enclave_cert();
            (root_cert.to_vec(), compute_cert.to_vec())
        };
        println!("vc-server: send policy");
        match self_.communicate(&RuntimeManagerRequest::Initialize(
            policy_json.to_string(),
            vec![compute_cert, root_cert],
        ))? {
            RuntimeManagerResponse::Status(Status::Success) => (),
            resp => {
                return Err(VeracruzServerError::IceCapError(
                    IceCapError::UnexpectedRuntimeManagerResponse(resp),
                ))
            }
        }
        Ok(self_)
    }

    fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError> {
        match self.communicate(&RuntimeManagerRequest::NewTlsSession)? {
            RuntimeManagerResponse::TlsSession(session_id) => Ok(session_id),
            resp => Err(VeracruzServerError::IceCapError(
                IceCapError::UnexpectedRuntimeManagerResponse(resp),
            )),
        }
    }

    fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
        match self.communicate(&RuntimeManagerRequest::CloseTlsSession(session_id))? {
            RuntimeManagerResponse::Status(Status::Success) => Ok(()),
            resp => Err(VeracruzServerError::IceCapError(
                IceCapError::UnexpectedRuntimeManagerResponse(resp),
            )),
        }
    }

    fn tls_data(
        &mut self,
        session_id: u32,
        input: Vec<u8>,
    ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
        match self.communicate(&RuntimeManagerRequest::SendTlsData(session_id, input))? {
            RuntimeManagerResponse::Status(Status::Success) => (),
            resp => {
                return Err(VeracruzServerError::IceCapError(
                    IceCapError::UnexpectedRuntimeManagerResponse(resp),
                ))
            }
        }

        let mut acc = Vec::new();
        let active = loop {
            if !self.tls_data_needed(session_id)? {
                break true;
            }
            match self.communicate(&RuntimeManagerRequest::GetTlsData(session_id))? {
                RuntimeManagerResponse::TlsData(data, active) => {
                    acc.push(data);
                    if !active {
                        break false;
                    }
                }
                resp => return Err(IceCapError::UnexpectedRuntimeManagerResponse(resp).into()),
            };
        };

        Ok((
            active,
            match acc.len() {
                0 => None,
                _ => Some(acc),
            },
        ))
    }

    fn shutdown_isolate(&mut self) -> Result<(), Box<dyn Error>> {
        match self.0.take() {
            Some(realm) => {
                realm.shutdown()?;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl Drop for VeracruzServerIceCapCCA {
    fn drop(&mut self) {
        if let Err(err) = self.shutdown_isolate() {
            panic!("Realm failed to shutdown: {}", err)
        }
    }
}
