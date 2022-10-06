//! Nitro-Enclave-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "nitro")]
pub mod veracruz_server_nitro {
    use crate::common::{VeracruzServer, VeracruzServerError};
    use base64;
    use io_utils::{
        http::send_proxy_attestation_server_start,
        nitro::NitroEnclave,
    };
    use policy_utils::policy::Policy;
    use reqwest;
    use std::{env, error::Error};
    use uuid::Uuid;
    use veracruz_utils::runtime_manager_message::{
        RuntimeManagerRequest, RuntimeManagerResponse, Status,
    };

    /// Path of the Runtime Manager enclave EIF file.
    const RUNTIME_MANAGER_EIF_PATH: &str = "../runtime-manager/runtime_manager.eif";
    /// The protocol to use when interacting with the proxy attestation server.

    pub struct VeracruzServerNitro {
        enclave: NitroEnclave,
    }

    impl VeracruzServer for VeracruzServerNitro {
        fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
            // Set up, initialize Nitro Root Enclave
            let policy: Policy = Policy::from_json(policy_json)?;

            let (challenge_id, challenge) = send_proxy_attestation_server_start(
                crate::server::VERAISON_VERIFIER_IP_ADDRESS,
            )
            .map_err(|e| {
                eprintln!(
                    "Failed to start proxy attestation process.  Error produced: {}.",
                    e
                );

                e
            })?;

            println!("VeracruzServerNitro::new instantiating Runtime Manager");
            let runtime_manager_eif_path = env::var("RUNTIME_MANAGER_EIF_PATH")
                .unwrap_or_else(|_| RUNTIME_MANAGER_EIF_PATH.to_string());
            #[cfg(feature = "debug")]
            let runtime_manager_enclave = {
                println!("Starting Runtime Manager enclave in debug mode");
                NitroEnclave::new(
                    false,
                    &runtime_manager_eif_path,
                    true,
                    *policy.max_memory_mib(),
                )?
            };
            #[cfg(not(feature = "debug"))]
            let runtime_manager_enclave = {
                println!("Starting Runtime Manager enclave in release mode");
                NitroEnclave::new(
                    false,
                    &runtime_manager_eif_path,
                    false,
                    *policy.max_memory_mib(),
                )?
            };
            println!("VeracruzServerNitro::new NitroEnclave::new returned");
            let meta = Self {
                enclave: runtime_manager_enclave,
            };
            println!("VeracruzServerNitro::new Runtime Manager instantiated. Calling initialize");

            let (attestation_doc, csr) = {
                let attestation = RuntimeManagerRequest::Attestation(challenge, challenge_id);
                meta.enclave
                    .send_buffer(&bincode::serialize(&attestation)?)?;
                // read the response
                let response = meta.enclave.receive_buffer()?;
                match bincode::deserialize(&response[..])? {
                    RuntimeManagerResponse::AttestationData(doc, csr) => (doc, csr),
                    response_message => {
                        return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                            response_message,
                        ))
                    }
                }
            };

            let cert_chain = post_native_attestation_token(
                //policy.proxy_attestation_server_url(),
                crate::server::VERAISON_VERIFIER_IP_ADDRESS,
                &attestation_doc,
                &csr,
                challenge_id,
            )?;

            let initialize: RuntimeManagerRequest =
                RuntimeManagerRequest::Initialize(policy_json.to_string(), cert_chain);

            let encoded_buffer: Vec<u8> = bincode::serialize(&initialize)?;
            meta.enclave.send_buffer(&encoded_buffer)?;

            // read the response
            let status_buffer = meta.enclave.receive_buffer()?;

            let message: RuntimeManagerResponse = bincode::deserialize(&status_buffer[..])?;
            let status = match message {
                RuntimeManagerResponse::Status(status) => status,
                _ => return Err(VeracruzServerError::InvalidRuntimeManagerResponse(message)),
            };
            match status {
                Status::Success => (),
                _ => return Err(VeracruzServerError::Status(status)),
            }
            println!("VeracruzServerNitro::new complete. Returning");
            Ok(meta)
        }

        fn plaintext_data(&mut self, _data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError> {
            Err(VeracruzServerError::UnimplementedError)
        }

        fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError> {
            let nls_message = RuntimeManagerRequest::NewTlsSession;
            let nls_buffer = bincode::serialize(&nls_message)?;
            self.enclave.send_buffer(&nls_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerResponse = bincode::deserialize(&received_buffer)?;
            let session_id = match received_message {
                RuntimeManagerResponse::TlsSession(sid) => sid,
                _ => {
                    return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        received_message,
                    ))
                }
            };
            Ok(session_id)
        }

        fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
            let cts_message = RuntimeManagerRequest::CloseTlsSession(session_id);
            let cts_buffer = bincode::serialize(&cts_message)?;

            self.enclave.send_buffer(&cts_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerResponse = bincode::deserialize(&received_buffer)?;
            match received_message {
                RuntimeManagerResponse::Status(_status) => Ok(()),

                _ => Err(VeracruzServerError::Status(Status::Fail)),
            }
        }

        fn tls_data(
            &mut self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            let std_message: RuntimeManagerRequest =
                RuntimeManagerRequest::SendTlsData(session_id, input);
            let std_buffer: Vec<u8> = bincode::serialize(&std_message)?;

            self.enclave.send_buffer(&std_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerResponse = bincode::deserialize(&received_buffer)?;
            match received_message {
                RuntimeManagerResponse::Status(status) => match status {
                    Status::Success => (),
                    _ => return Err(VeracruzServerError::Status(status)),
                },
                _ => {
                    return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        received_message,
                    ))
                }
            }

            let mut active_flag = true;
            let mut ret_array = Vec::new();
            while self.tls_data_needed(session_id)? {
                let gtd_message = RuntimeManagerRequest::GetTlsData(session_id);
                let gtd_buffer: Vec<u8> = bincode::serialize(&gtd_message)?;

                self.enclave.send_buffer(&gtd_buffer)?;

                let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

                let received_message: RuntimeManagerResponse =
                    bincode::deserialize(&received_buffer)?;
                match received_message {
                    RuntimeManagerResponse::TlsData(data, alive) => {
                        active_flag = alive;
                        ret_array.push(data);
                    }
                    _ => return Err(VeracruzServerError::Status(Status::Fail)),
                }
            }

            Ok((
                active_flag,
                if !ret_array.is_empty() {
                    Some(ret_array)
                } else {
                    None
                },
            ))
        }

        fn shutdown_isolate(&mut self) -> Result<(), Box<dyn Error>> {
            // Don't do anything. The enclave gets shutdown when the
            // `NitroEnclave` object inside `VeracruzServerNitro` is dropped
            Ok(())
        }
    }

    impl Drop for VeracruzServerNitro {
        fn drop(&mut self) {
            if let Err(err) = self.shutdown_isolate() {
                println!(
                    "VeracruzServerNitro::drop failed in call to self.shutdown_isolate:{:?}",
                    err
                )
            }
        }
    }

    impl VeracruzServerNitro {
        fn tls_data_needed(&self, session_id: u32) -> Result<bool, VeracruzServerError> {
            let gtdn_message = RuntimeManagerRequest::GetTlsDataNeeded(session_id);
            let gtdn_buffer: Vec<u8> = bincode::serialize(&gtdn_message)?;

            self.enclave.send_buffer(&gtdn_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerResponse = bincode::deserialize(&received_buffer)?;
            let tls_data_needed = match received_message {
                RuntimeManagerResponse::TlsDataNeeded(needed) => needed,
                _ => return Err(VeracruzServerError::Status(Status::Fail)),
            };
            Ok(tls_data_needed)
        }
    }

    fn post_attestation_doc_csr(url: &str, att_doc: &[u8], csr: &[u8]) -> Result<Vec<u8>, VeracruzServerError> {
        let client_builder = reqwest::blocking::ClientBuilder::new();

        let client = client_builder.build()
            .map_err(|err| {
                VeracruzServerError::ReqwestError(err)
            })?;
        let form = reqwest::blocking::multipart::Form::new()
            .text("token", base64::encode(att_doc))
            .text("csr", base64::encode(csr));

        let response = client.post(url)
            .multipart(form)
            .send()
            .map_err(|err| {
                VeracruzServerError::ReqwestError(err)
            })?;
        let cert_chain = match response.status() {
            reqwest::StatusCode::OK => {
                response.bytes()
                .map_err(|err| {
                    VeracruzServerError::ReqwestError(err)
                })?
            }
            bad_status => {
                return Err(VeracruzServerError::HttpError(bad_status));
            }
        };
        return Ok(cert_chain.to_vec());
    }

    /// Send the native (AWS Nitro) attestation token to the proxy attestation server
    fn post_native_attestation_token(
        proxy_attestation_server_url: &str,
        att_doc: &[u8],
        csr: &[u8],
        challenge_id: Uuid,
    ) -> Result<Vec<u8>, VeracruzServerError> {
        let url = format!("http://{:}/proxy/v1/Nitro/{:}", proxy_attestation_server_url, challenge_id);
        let cert_chain = post_attestation_doc_csr(&url, att_doc, csr).map_err(|e| {
            e
        })?;
        Ok(cert_chain.to_vec())
    }
}
