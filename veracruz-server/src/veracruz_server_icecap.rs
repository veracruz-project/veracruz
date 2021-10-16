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

use crate::{
    send_proxy_attestation_server_start,
    veracruz_server::{VeracruzServer, VeracruzServerError},
};
use bincode::{deserialize, serialize};
use err_derive::Error;
use std::{
    env,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem::size_of,
    path::PathBuf,
    process::{Child, Command, ExitStatus},
    result,
    string::ToString,
};
use veracruz_utils::{
    platform::icecap::message::{Header, Request, Response},
    policy::policy::Policy,
};

// For now, certain IceCap host configuration parameters must be passed as environment variables.
// See veracruz/icecap/nix/host/config.nix for an illustration of their usage.
const VERACRUZ_ICECAP_HOST_COMMAND_ENV: &str = "VERACRUZ_ICECAP_HOST_COMMAND";
const VERACRUZ_ICECAP_REALM_ID_ENV: &str = "VERACRUZ_ICECAP_REALM_ID";
const VERACRUZ_ICECAP_REALM_SPEC_ENV: &str = "VERACRUZ_ICECAP_REALM_SPEC";
const VERACRUZ_ICECAP_REALM_ENDPOINT_ENV: &str = "VERACRUZ_ICECAP_REALM_ENDPOINT";

const VERACRUZ_ICECAP_HOST_COMMAND_DEFAULT: &str = "icecap-host";

const FIRMWARE_VERSION: &str = "0.3.0";

type Result<T> = result::Result<T, VeracruzServerError>;

/// Class of IceCap-specific errors.
#[derive(Debug, Error)]
pub enum IceCapError {
    #[error(display = "IceCap: Realm channel error: {}", _0)]
    RealmChannelError(io::Error),
    #[error(display = "IceCap: Serialization error: {}", _0)]
    SerializationError(bincode::Error),
    #[error(display = "IceCap: Shadow VMM spawn error: {}", _0)]
    ShadowVmmSpawnError(io::Error),
    #[error(display = "IceCap: Shadow VMM exit status error: {}", exit_status)]
    ShadowVMMExitStatusError { exit_status: ExitStatus },
    #[error(display = "IceCap: Shadow VMM stop error: {}", _0)]
    ShadowVMMStopError(io::Error),
    #[error(display = "IceCap: Unexpected response from runtime manager: {:?}", _0)]
    UnexpectedRuntimeManagerResponse(Response),
    #[error(display = "IceCap: Missing environment variable: {}", variable)]
    MissingEnvironmentVariable { variable: String },
    #[error(display = "IceCap: Invalid environment variable value: {}", variable)]
    InvalidEnvironemntVariableValue { variable: String },
}

impl IceCapError {
    // For point-free error handling
    fn hoist<T>(f: impl Fn(T) -> IceCapError) -> impl Fn(T) -> VeracruzServerError {
        move |inner| VeracruzServerError::IceCapError(f(inner))
    }
}

struct Configuration {
    icecap_host_command: PathBuf,
    realm_id: usize,
    realm_spec: PathBuf,
    realm_endpoint: PathBuf,
}

impl Configuration {
    fn env_var(var: &str) -> Result<String> {
        env::var(var).map_err(|_| {
            VeracruzServerError::IceCapError(IceCapError::MissingEnvironmentVariable {
                variable: var.to_string(),
            })
        })
    }

    fn from_env() -> Result<Self> {
        Ok(Self {
            icecap_host_command: Self::env_var(VERACRUZ_ICECAP_HOST_COMMAND_ENV)
                .map(PathBuf::from)
                .unwrap_or(VERACRUZ_ICECAP_HOST_COMMAND_DEFAULT.into()),
            realm_id: Self::env_var(VERACRUZ_ICECAP_REALM_ID_ENV)?
                .parse::<usize>()
                .map_err(|_| {
                    VeracruzServerError::IceCapError(IceCapError::InvalidEnvironemntVariableValue {
                        variable: VERACRUZ_ICECAP_REALM_ID_ENV.to_string(),
                    })
                })?,
            realm_spec: Self::env_var(VERACRUZ_ICECAP_REALM_SPEC_ENV)?.into(),
            realm_endpoint: Self::env_var(VERACRUZ_ICECAP_REALM_ENDPOINT_ENV)?.into(),
        })
    }

    fn icecap_host_command(&self) -> Command {
        // HACK
        // For now, at the pinned version of IceCap, realms must run on core 0.
        let mut command = Command::new("taskset");
        command.arg("0x1");
        command.arg(&self.icecap_host_command);
        command
    }

    // HACK clean up in case of previous failure
    fn hack_ensure_not_realm_running() {
        Command::new("pkill").arg("icecap-host").status().unwrap();
    }

    fn ensure_successful(exit_status: ExitStatus) -> Result<()> {
        if exit_status.success() {
            Ok(())
        } else {
            Err(VeracruzServerError::IceCapError(
                IceCapError::ShadowVMMExitStatusError { exit_status },
            ))
        }
    }

    fn create_realm(&self) -> Result<()> {
        Self::ensure_successful(
            self.icecap_host_command()
                .arg("create")
                .arg(format!("{}", self.realm_id))
                .arg(&self.realm_spec)
                .status()
                .map_err(IceCapError::hoist(IceCapError::ShadowVmmSpawnError))?,
        )
    }

    fn run_realm(&self) -> Result<Child> {
        let virtual_node_id: usize = 0;
        let child = self
            .icecap_host_command()
            .arg("run")
            .arg(format!("{}", self.realm_id))
            .arg(format!("{}", virtual_node_id))
            .spawn()
            .map_err(IceCapError::hoist(IceCapError::ShadowVmmSpawnError))?;
        Ok(child)
    }

    fn destroy_realm(&self) -> Result<()> {
        Self::hack_ensure_not_realm_running();
        Self::ensure_successful(
            self.icecap_host_command()
                .arg("destroy")
                .arg(format!("{}", self.realm_id))
                .status()
                .map_err(IceCapError::hoist(IceCapError::ShadowVmmSpawnError))?,
        )
    }
}

/// IceCap implementation of 'VeracruzServer'
pub struct VeracruzServerIceCap {
    configuration: Configuration,
    realm_channel: File,
    realm_process: Child,
}

impl VeracruzServer for VeracruzServerIceCap {
    fn new(policy_json: &str) -> Result<Self> {
        let policy: Policy = Policy::from_json(policy_json)?;

        let configuration = Configuration::from_env()?;
        configuration.destroy_realm()?; // HACK clean up in case of previous failure
        configuration.create_realm()?;
        let realm_process = configuration.run_realm()?;
        let realm_channel = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&configuration.realm_endpoint)
            .map_err(IceCapError::hoist(IceCapError::RealmChannelError))?;
        let server = Self {
            configuration,
            realm_channel,
            realm_process,
        };

        match server.send(&Request::Initialize {
            policy_json: policy_json.to_string(),
        })? {
            Response::Initialize => (),
            resp => {
                return Err(VeracruzServerError::IceCapError(
                    IceCapError::UnexpectedRuntimeManagerResponse(resp),
                ))
            }
        }

        let (challenge, device_id) = {
            let resp = send_proxy_attestation_server_start(
                policy.proxy_attestation_server_url(),
                "psa",
                FIRMWARE_VERSION,
            )?;
            if !resp.has_psa_attestation_init() {
                return Err(VeracruzServerError::MissingFieldError(
                    "psa_attestation_init",
                ));
            }
            transport_protocol::parse_psa_attestation_init(resp.get_psa_attestation_init())?
        };

        let (token, csr) = match server.send(&Request::Attestation {
            challenge,
            device_id,
        })? {
            Response::Attestation { token, csr } => (token, csr),
            resp => {
                return Err(VeracruzServerError::IceCapError(
                    IceCapError::UnexpectedRuntimeManagerResponse(resp),
                ))
            }
        };

        let (root_cert, compute_cert) = {
            let req =
                transport_protocol::serialize_native_psa_attestation_token(&token, &csr, device_id)
                    .map_err(VeracruzServerError::TransportProtocolError)?;
            let req = base64::encode(&req);
            let url = format!(
                "{:}/PSA/AttestationToken",
                policy.proxy_attestation_server_url()
            );
            let resp = crate::post_buffer(&url, &req)?;
            let resp = base64::decode(&resp)?;
            let pasr = transport_protocol::parse_proxy_attestation_server_response(&resp)
                .map_err(VeracruzServerError::TransportProtocolError)?;
            let cert_chain = pasr.get_cert_chain();
            let root_cert = cert_chain.get_root_cert();
            let compute_cert = cert_chain.get_enclave_cert();
            (root_cert.to_vec(), compute_cert.to_vec())
        };

        match server.send(&Request::CertificateChain {
            root_cert,
            compute_cert,
        })? {
            Response::CertificateChain => (),
            resp => {
                return Err(VeracruzServerError::IceCapError(
                    IceCapError::UnexpectedRuntimeManagerResponse(resp),
                ))
            }
        }

        Ok(server)
    }

    fn plaintext_data(&self, _data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        unimplemented!()
    }

    fn new_tls_session(&self) -> Result<u32> {
        match self.send(&Request::NewTlsSession)? {
            Response::NewTlsSession(session_id) => Ok(session_id),
            resp => Err(VeracruzServerError::IceCapError(
                IceCapError::UnexpectedRuntimeManagerResponse(resp),
            )),
        }
    }

    fn close_tls_session(&mut self, session_id: u32) -> Result<()> {
        match self.send(&Request::CloseTlsSession(session_id))? {
            Response::CloseTlsSession => Ok(()),
            resp => Err(VeracruzServerError::IceCapError(
                IceCapError::UnexpectedRuntimeManagerResponse(resp),
            )),
        }
    }

    fn tls_data(
        &mut self,
        session_id: u32,
        input: Vec<u8>,
    ) -> Result<(bool, Option<Vec<Vec<u8>>>)> {
        match self.send(&Request::SendTlsData(session_id, input))? {
            Response::SendTlsData => (),
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
            match self.send(&Request::GetTlsData(session_id))? {
                Response::GetTlsData(active, data) => {
                    acc.push(data);
                    if !active {
                        break false;
                    }
                }
                resp => {
                    return Err(VeracruzServerError::IceCapError(
                        IceCapError::UnexpectedRuntimeManagerResponse(resp),
                    ))
                }
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

    fn close(&mut self) -> Result<bool> {
        self.realm_process
            .kill()
            .map_err(IceCapError::hoist(IceCapError::ShadowVMMStopError))?;
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
        // We have '&self' rather than '&mut self', so we must use 'impl Write for &File'
        // rather than 'impl Write for File'.
        let mut realm_channel = &self.realm_channel;

        let msg =
            serialize(request).map_err(IceCapError::hoist(IceCapError::SerializationError))?;
        let header = (msg.len() as Header).to_le_bytes();
        realm_channel
            .write(&header)
            .map_err(IceCapError::hoist(IceCapError::RealmChannelError))?;
        realm_channel
            .write(&msg)
            .map_err(IceCapError::hoist(IceCapError::RealmChannelError))?;
        let mut header_bytes = [0; size_of::<Header>()];
        realm_channel
            .read_exact(&mut header_bytes)
            .map_err(IceCapError::hoist(IceCapError::RealmChannelError))?;
        let header = u32::from_le_bytes(header_bytes);
        let mut resp_bytes = vec![0; header as usize];
        realm_channel
            .read_exact(&mut resp_bytes)
            .map_err(IceCapError::hoist(IceCapError::RealmChannelError))?;
        let resp = deserialize(&resp_bytes)
            .map_err(IceCapError::hoist(IceCapError::SerializationError))?;
        Ok(resp)
    }

    fn tls_data_needed(&self, session_id: u32) -> Result<bool> {
        match self.send(&Request::GetTlsDataNeeded(session_id))? {
            Response::GetTlsDataNeeded(needed) => Ok(needed),
            resp => Err(VeracruzServerError::IceCapError(
                IceCapError::UnexpectedRuntimeManagerResponse(resp),
            )),
        }
    }
}
