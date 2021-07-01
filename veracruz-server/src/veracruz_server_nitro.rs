//! Nitro-Enclave-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "nitro")]
pub mod veracruz_server_nitro {
    use crate::ec2_instance::EC2Instance;
    use crate::veracruz_server::{VeracruzServer, VeracruzServerError};
    use lazy_static::lazy_static;
    use std::sync::Mutex;
    use veracruz_utils::platform::Platform;
    use veracruz_utils::platform::nitro::nitro::{NitroRootEnclaveMessage, RuntimeManagerMessage, NitroStatus};
    use veracruz_utils::platform::nitro::nitro_enclave::{NitroEnclave, NitroError};
    use veracruz_utils::policy::policy::Policy;

    const RUNTIME_MANAGER_EIF_PATH: &str = "../runtime-manager/runtime_manager.eif";
    const NITRO_ROOT_ENCLAVE_EIF_PATH: &str = "../nitro-root-enclave/nitro_root_enclave.eif";
    const NITRO_ROOT_ENCLAVE_SERVER_PATH: &str =
        "../nitro-root-enclave-server/target/debug/nitro-root-enclave-server";

    lazy_static! {
        //static ref NRE_CONTEXT: Mutex<Option<NitroEnclave>> = Mutex::new(None);
        static ref NRE_CONTEXT: Mutex<Option<EC2Instance>> = Mutex::new(None);
    }

    pub struct VeracruzServerNitro {
        enclave: NitroEnclave,
    }

    impl VeracruzServer for VeracruzServerNitro {
        fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
            // Set up, initialize Nitro Root Enclave
            let policy: Policy =
                Policy::from_json(policy_json)?;

            {
                let mut nre_guard = NRE_CONTEXT.lock()?;
                if nre_guard.is_none() {
                    println!("NITRO ROOT ENCLAVE IS UNINITIALIZED.");
                    let runtime_manager_hash = policy
                        .runtime_manager_hash(&Platform::Nitro)
                        .map_err(|err| VeracruzServerError::VeracruzUtilError(err))?;
                    let ip_string = std::env::var("TABASCO_IP_ADDRESS").unwrap_or("127.0.0.1".to_string());
                    let ip_addr = format!("{:}:3010", ip_string);
                    let nre_context =
                        VeracruzServerNitro::native_attestation(&ip_addr, &runtime_manager_hash)?;
                    *nre_guard = Some(nre_context);
                }
            }

            println!("VeracruzServerNitro::new native_attestation complete. instantiating Runtime Manager");
            #[cfg(feature = "debug")]
            let runtime_manager_enclave = {
                println!("Starting Runtime Manager enclave in debug mode");
                NitroEnclave::new(
                    false,
                    RUNTIME_MANAGER_EIF_PATH,
                    true,
                    Some(VeracruzServerNitro::veracruz_server_ocall_handler),
                )
                .map_err(|err| VeracruzServerError::NitroError(err))?
            };
            #[cfg(not(feature = "debug"))]
            let runtime_manager_enclave = {
                println!("Starting Runtime Manager enclave in release mode");
                NitroEnclave::new(
                    false,
                    RUNTIME_MANAGER_EIF_PATH,
                    false,
                    Some(VeracruzServerNitro::veracruz_server_ocall_handler),
                )
                .map_err(|err| VeracruzServerError::NitroError(err))?
            };
            println!("VeracruzServerNitro::new NitroEnclave::new returned");
            let meta = Self {
                enclave: runtime_manager_enclave,
            };
            println!("VeracruzServerNitro::new Runtime Manager instantiated. Calling initialize");
            std::thread::sleep(std::time::Duration::from_millis(10000));

            // Send the StartProxy message, receive the ChallengeData message in response
            let (challenge, challenge_id) = {
                let start_proxy: NitroRootEnclaveMessage = NitroRootEnclaveMessage::StartProxy;
                let encoded_buffer: Vec<u8> = bincode::serialize(&start_proxy)?;
                let response_buffer = {
                    let mut nre_guard = NRE_CONTEXT.lock()?;
                    match &mut *nre_guard {
                        Some(nre) => {
                            nre.send_buffer(&encoded_buffer)?;
                            nre.receive_buffer()?
                        },
                        None => return Err(VeracruzServerError::UninitializedEnclaveError),
                    }
                };
                let message: NitroRootEnclaveMessage = bincode::deserialize(&response_buffer)?;
                match message {
                    NitroRootEnclaveMessage::ChallengeData(chall, id) => (chall, id),
                    _ => return Err(VeracruzServerError::InvalidNitroRootEnclaveMessage(message)),
                }
            };

            let initialize: RuntimeManagerMessage = RuntimeManagerMessage::Initialize(policy_json.to_string(), challenge, challenge_id);

            let encoded_buffer: Vec<u8> = bincode::serialize(&initialize)?;
            meta.enclave.send_buffer(&encoded_buffer)?;

            // read the response
            let status_buffer = meta.enclave.receive_buffer()?;

            let message: RuntimeManagerMessage = bincode::deserialize(&status_buffer[..])?;
            let status = match message {
                RuntimeManagerMessage::Status(status) => status,
                _ => return Err(VeracruzServerError::RuntimeManagerMessageStatus(message)),
            };
            match status {
                NitroStatus::Success => (),
                _ => return Err(VeracruzServerError::NitroStatus(status)),
            }
            println!("VeracruzServerNitro::new complete. Returning");
            return Ok(meta);
        }

        fn plaintext_data(&self, _data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError> {
            return Err(VeracruzServerError::UnimplementedError);
        }

        fn new_tls_session(&self) -> Result<u32, VeracruzServerError> {
            let nls_message = RuntimeManagerMessage::NewTLSSession;
            let nls_buffer = bincode::serialize(&nls_message)?;
            self.enclave.send_buffer(&nls_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            let session_id = match received_message {
                RuntimeManagerMessage::TLSSession(sid) => sid,
                _ => return Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
            };
            return Ok(session_id);
        }

        fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
            let cts_message = RuntimeManagerMessage::CloseTLSSession(session_id);
            let cts_buffer = bincode::serialize(&cts_message)?;

            self.enclave.send_buffer(&cts_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            return match received_message {
                RuntimeManagerMessage::Status(_status) => Ok(()),
                _ => Err(VeracruzServerError::NitroStatus(NitroStatus::Fail)),
            };
        }

        fn tls_data(
            &mut self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            let std_message: RuntimeManagerMessage = RuntimeManagerMessage::SendTLSData(session_id, input);
            let std_buffer: Vec<u8> = bincode::serialize(&std_message)?;

            self.enclave.send_buffer(&std_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            match received_message {
                RuntimeManagerMessage::Status(status) => match status {
                    NitroStatus::Success => (),
                    _ => return Err(VeracruzServerError::NitroStatus(status)),
                },
                _ => return Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
            }

            let mut active_flag = true;
            let mut ret_array = Vec::new();
            while self.tls_data_needed(session_id)? {
                let gtd_message = RuntimeManagerMessage::GetTLSData(session_id);
                let gtd_buffer: Vec<u8> = bincode::serialize(&gtd_message)?;

                self.enclave.send_buffer(&gtd_buffer)?;

                let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

                let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
                match received_message {
                    RuntimeManagerMessage::TLSData(data, alive) => {
                        active_flag = alive;
                        ret_array.push(data);
                    }
                    _ => return Err(VeracruzServerError::NitroStatus(NitroStatus::Fail)),
                }
            }

            Ok((
                active_flag,
                if ret_array.len() > 0 {
                    Some(ret_array)
                } else {
                    None
                },
            ))
        }

        fn close(&mut self) -> Result<bool, VeracruzServerError> {
            let re_message: RuntimeManagerMessage = RuntimeManagerMessage::ResetEnclave;
            let re_buffer: Vec<u8> = bincode::serialize(&re_message)?;

            self.enclave.send_buffer(&re_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;
            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            return match received_message {
                RuntimeManagerMessage::Status(status) => match status {
                    NitroStatus::Success => Ok(true),
                    _ => Err(VeracruzServerError::NitroStatus(status)),
                },
                _ => Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
            };
        }
    }

    impl Drop for VeracruzServerNitro {
        fn drop(&mut self) {
            match self.close() {
                Err(err) => println!("VeracruzServerNitro::drop failed in call to self.close:{:?}, we will persevere, though.", err),
                _ => (),
            }
        }
    }

    impl VeracruzServerNitro {
        fn veracruz_server_ocall_handler(input_buffer: Vec<u8>) -> Result<Vec<u8>, NitroError> {
            let return_buffer: Vec<u8> = {
                let mut nre_guard = NRE_CONTEXT.lock().map_err(|_| NitroError::MutexError)?;
                match &mut *nre_guard {
                    Some(nre) => {
                        nre.send_buffer(&input_buffer).map_err(|err| {
                            println!(
                                "VeracruzServerNitro::veracruz_server_ocall_handler send_buffer failed:{:?}",
                                err
                            );
                            NitroError::EC2Error
                        })?;
                        let ret_buffer = nre.receive_buffer().map_err(|err| {
                            println!(
                                "VeracruzServerNitro::veracruz_server_ocall_handler receive_buffer failed:{:?}",
                                err
                            );
                            NitroError::EC2Error
                        })?;
                        ret_buffer
                    }
                    None => return Err(NitroError::EC2Error),
                }
            };
            return Ok(return_buffer);
        }

        fn tls_data_needed(&self, session_id: u32) -> Result<bool, VeracruzServerError> {
            let gtdn_message = RuntimeManagerMessage::GetTLSDataNeeded(session_id);
            let gtdn_buffer: Vec<u8> = bincode::serialize(&gtdn_message)?;

            self.enclave.send_buffer(&gtdn_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            let tls_data_needed = match received_message {
                RuntimeManagerMessage::TLSDataNeeded(needed) => needed,
                _ => return Err(VeracruzServerError::NitroStatus(NitroStatus::Fail)),
            };
            return Ok(tls_data_needed);
        }

        fn native_attestation(
            proxy_attestation_server_url: &str,
            _runtime_manager_hash: &str,
            //) -> Result<NitroEnclave, VeracruzServerError> {
        ) -> Result<EC2Instance, VeracruzServerError> {
            println!("VeracruzServerNitro::native_attestation started");

            println!("Starting EC2 instance");
            let nre_instance = EC2Instance::new().map_err(|err| VeracruzServerError::EC2Error(err))?;

            nre_instance
                .upload_file(
                    NITRO_ROOT_ENCLAVE_EIF_PATH,
                    "/home/ec2-user/nitro_root_enclave.eif",
                )
                .map_err(|err| VeracruzServerError::EC2Error(err))?;
            nre_instance
                .upload_file(
                    NITRO_ROOT_ENCLAVE_SERVER_PATH,
                    "/home/ec2-user/nitro-root-enclave-server",
                )
                .map_err(|err| VeracruzServerError::EC2Error(err))?;

            nre_instance
                .execute_command("nitro-cli-config -t 2 -m 512")
                .map_err(|err| VeracruzServerError::EC2Error(err))?;
            #[cfg(feature = "debug")]
            let server_command: String = format!(
                "nohup /home/ec2-user/nitro-root-enclave-server --debug {:} &> nitro_server.log &",
                proxy_attestation_server_url
            );
            #[cfg(not(feature = "debug"))]
            let server_command: String = format!(
                "nohup /home/ec2-user/nitro-root-enclave-server {:} &> nitro_server.log &",
                proxy_attestation_server_url
            );
            nre_instance
                .execute_command(&server_command)
                .map_err(|err| VeracruzServerError::EC2Error(err))?;

            println!("Waiting for NRE Instance to authenticate.");
            std::thread::sleep(std::time::Duration::from_millis(15000));

            println!("veracruz_server_tz::native_attestation returning Ok");
            return Ok(nre_instance);
        }
    }
}
