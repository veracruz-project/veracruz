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

    use crate::common::{VeracruzServerError, VeracruzServerResult};
    use io_utils::nitro::NitroEnclave;
    use log::error;
    use policy_utils::policy::Policy;
    use proxy_attestation_client;
    use std::{env, error::Error};
    use std::io::{Read, Write};
    use std::sync::{Arc, Condvar, Mutex};
    use veracruz_utils::runtime_manager_message::{
        RuntimeManagerRequest, RuntimeManagerResponse, Status,
    };

    /// Path of the Runtime Manager enclave EIF file.
    const RUNTIME_MANAGER_EIF_PATH: &str = "../runtime-manager/runtime_manager.eif";
    /// The protocol to use when interacting with the proxy attestation server.

    struct VeracruzServerNitro {
        enclave: NitroEnclave,
    }

    impl VeracruzServerNitro {
        fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
            // Set up, initialize Nitro Root Enclave
            let policy: Policy = Policy::from_json(policy_json)?;

            let (challenge_id, challenge) = proxy_attestation_client::start_proxy_attestation(
                policy.proxy_attestation_server_url(),
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

            let cert_chain = proxy_attestation_client::complete_proxy_attestation_nitro(
                policy.proxy_attestation_server_url(),
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
            loop {
                let gtd_message = RuntimeManagerRequest::GetTlsData(session_id);
                let gtd_buffer: Vec<u8> = bincode::serialize(&gtd_message)?;

                self.enclave.send_buffer(&gtd_buffer)?;

                let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

                let received_message: RuntimeManagerResponse =
                    bincode::deserialize(&received_buffer)?;
                match received_message {
                    RuntimeManagerResponse::TlsData(data, alive) => {
                        if !alive {
                            active_flag = false
                        }
                        if data.len() == 0 {
                            break;
                        }
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
        fn shutdown_isolate(&mut self) -> Result<(), Box<dyn Error>> {
            // Don't do anything. The enclave gets shutdown when the
            // `NitroEnclave` object inside `VeracruzServerNitro` is dropped
            Ok(())
        }
    }

////////////////////////////////////////////////////////////////////////////////

//xx This should perhaps be called VeracruzEnclave?
pub struct VeracruzServer(
    Arc<(Mutex<Option<VeracruzServerNitro>>, Condvar)>
);

//xx This should perhaps be called VeracruzConnection?
pub struct VeracruzSession {
    enclave: VeracruzServer,
    session_id: u32,
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl VeracruzServer {
    pub fn new(policy: &str) -> VeracruzServerResult<Self> {
        Ok(VeracruzServer(Arc::new((
            Mutex::new(Some(VeracruzServerNitro::new(policy)?)),
            Condvar::new(),
        ))))
    }
    pub fn clone(&self) -> Self {
        VeracruzServer(self.0.clone())
    }
    pub fn new_session(&mut self) -> VeracruzServerResult<VeracruzSession> {
        Ok(VeracruzSession {
            enclave: VeracruzServer(self.0.clone()),
            session_id: self
                .0
                .0
                .lock()
                .unwrap()
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?
                .new_tls_session()?,
            buffer: Arc::new(Mutex::new(vec![])),
        })
    }
}

impl VeracruzSession {
    pub fn clone(&self) -> Self {
        VeracruzSession {
            enclave: self.enclave.clone(),
            session_id: self.session_id,
            buffer: self.buffer.clone(),
        }
    }
}

impl Read for VeracruzSession {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        if buf.len() == 0 {
            Ok(0)
        } else {
            let mut enclave = self.enclave.0.0.lock().unwrap();
            loop {
                {
                    let mut buffer = self.buffer.lock().unwrap();
                    if enclave.is_none() || buffer.len() > 0 {
                        let n = std::cmp::min(buf.len(), buffer.len());
                        buf[0..n].clone_from_slice(&buffer[0..n]);
                        buffer.drain(0..n);
                        return Ok(n);
                    }
                }
                enclave = self.enclave.0.1.wait(enclave).unwrap();
            }
        }
    }
}

impl Write for VeracruzSession {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        if buf.len() > 0 {
            let mut mb_enclave = self.enclave.0.0.lock().unwrap();
            match mb_enclave.as_mut() {
                None => return Ok(0),
                Some(enclave) => {
                    let (active, output) =
                        match enclave.tls_data(self.session_id, buf.to_vec()) {
                            Ok(x) => x,
                            Err(e) => {
                                error!("tls_data gave error: {}", e);
                                (false, None)
                            }
                        };
                    if !active {
                        eprintln!("session write: !active");
                        mb_enclave.take();
                    }
                    let mut buffer = self.buffer.lock().unwrap();
                    let buffer_len = buffer.len();
                    for x1 in output {
                        for mut x in x1 {
                            buffer.append(&mut x);
                        }
                    }
                    if !active || (buffer_len == 0 && buf.len() > 0) {
                        self.enclave.0.1.notify_all();
                    }
                }
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}
