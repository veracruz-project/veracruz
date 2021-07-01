//! Arm TrustZone-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "tz")]
pub mod veracruz_server_tz {

    use crate::veracruz_server::*;
    use hex;
    use lazy_static::lazy_static;
    use log::debug;
    use optee_teec::{
        Context, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session, Uuid,
    };
    use std::{convert::TryInto, sync::{atomic::{AtomicBool, Ordering}, Mutex}};
    use veracruz_utils::{
        platform::{
            Platform,
            tz::{
                root_enclave_opcode::{TrustZoneRootEnclaveOpcode, TRUSTZONE_ROOT_ENCLAVE_UUID},
                runtime_manager_opcode::{RuntimeManagerOpcode, RUNTIME_MANAGER_UUID}
            },
        },
        policy::policy::Policy
    };

    lazy_static! {
        static ref CONTEXT: Mutex<Option<Context>> = Mutex::new(Some(Context::new().unwrap()));
        static ref TRUSTZONE_ROOT_ENCLAVE_INITIALIZED: AtomicBool = AtomicBool::new(false);
    }

    pub struct VeracruzServerTZ {
        runtime_manager_uuid: String,
    }

    impl VeracruzServer for VeracruzServerTZ {
        fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
            let policy: Policy =
                Policy::from_json(policy_json)?;

            if !TRUSTZONE_ROOT_ENCLAVE_INITIALIZED.load(Ordering::SeqCst) {
                let trustzone_root_enclave_uuid = Uuid::parse_str(&TRUSTZONE_ROOT_ENCLAVE_UUID.to_string())?;

                let runtime_manager_hash = {
                    match policy.runtime_manager_hash(&Platform::TrustZone) {
                        Ok(hash) => hash,
                        Err(_) => return Err(VeracruzServerError::MissingFieldError("runtime_manager_hash_tz")),
                    }
                };

                VeracruzServerTZ::native_attestation(
                    &policy.proxy_attestation_server_url(),
                    trustzone_root_enclave_uuid,
                    &runtime_manager_hash,
                )?;

                TRUSTZONE_ROOT_ENCLAVE_INITIALIZED.store(true, Ordering::SeqCst);
            }

            {
                let runtime_manager_uuid = Uuid::parse_str(&RUNTIME_MANAGER_UUID.to_string())?;
                let p0 = ParamTmpRef::new_input(&policy_json.as_bytes());

                let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
                let mut context_opt = CONTEXT.lock()?;
                let context = context_opt
                    .as_mut()
                    .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
                let mut session = context.open_session(runtime_manager_uuid)?;
                session.invoke_command(RuntimeManagerOpcode::Initialize as u32, &mut operation)?;
            }

            // Get a 'challenge' value from the root enclave for the compute enclave to use for attestation
            let trustzone_root_enclave_uuid = Uuid::parse_str(&TRUSTZONE_ROOT_ENCLAVE_UUID.to_string())?;
            let (challenge, challenge_id) = VeracruzServerTZ::start_local_attestation(trustzone_root_enclave_uuid)?;

            let mut csr: Vec<u8> = Vec::with_capacity(2048); // TODO: Don't do this
            {
                let runtime_manager_uuid = Uuid::parse_str(&RUNTIME_MANAGER_UUID.to_string())?;
                let p0 = ParamTmpRef::new_input(&challenge);
                let p1 = ParamTmpRef::new_output(&mut csr);

                let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
                let mut context_opt = CONTEXT.lock()?;
                let context = context_opt
                    .as_mut()
                    .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
                let mut session = context.open_session(runtime_manager_uuid)?;
                session.invoke_command(RuntimeManagerOpcode::GetCSR as u32, &mut operation)?;

                let (_, p1_output, _, _) = operation.parameters();
                unsafe {
                    let new_len = p1_output.updated_size();
                    csr.set_len(new_len);
                }
            }
            let mut cert_chain_buffer: Vec<u8> = Vec::with_capacity(3 * 2048); //TODO: Don't do this
            // cert lengths should be [u32] with 3 elements. But optee-utee doesn't
            // support a way to pass this in as a parameter. We aren't using these
            // values here, only passing them between OPTEE enclaves. So we're
            // going to leave it as [u8] and let the enclaves handle it
            let mut cert_lengths: Vec<u8> = Vec::with_capacity(3 * 4);// TODO: Unmagic these numbers
            {
                // call ProxyAttestation in the root enclave
                let root_enclave_uuid = Uuid::parse_str(&TRUSTZONE_ROOT_ENCLAVE_UUID.to_string())?;

                let p0 = ParamTmpRef::new_input(&*csr);
                let p1 = ParamValue::new(challenge_id, 0, ParamType::ValueInput);

                let p2 = ParamTmpRef::new_output(&mut cert_chain_buffer);
                let p3 = ParamTmpRef::new_output(&mut cert_lengths);
                let mut operation = Operation::new(0, p0, p1, p2, p3);
                let mut context_opt = CONTEXT.lock()?;
                let context = context_opt
                    .as_mut()
                    .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
                let mut session = context.open_session(root_enclave_uuid)?;
                session.invoke_command(TrustZoneRootEnclaveOpcode::ProxyAttestation as u32, &mut operation)
                    .map_err(|err| {
                        println!("veracruz_server_tz::new failed to invoke session.invoke_command failed:{:?}", err);
                        err
                    })?;
                let (_, _, p2_output, p3_output) = operation.parameters();
                unsafe {
                    let ccb_len = p2_output.updated_size();
                    cert_chain_buffer.set_len(ccb_len);
                    let cl_len = p3_output.updated_size();
                    cert_lengths.set_len(cl_len);
                }
            }
            {
                // call PopulateCertificates in the runtime enclave
                let runtime_manager_uuid = Uuid::parse_str(&RUNTIME_MANAGER_UUID.to_string())?;
                let p0 = ParamTmpRef::new_input(&cert_chain_buffer);
                let p1 = ParamTmpRef::new_input(&mut cert_lengths);

                let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
                let mut context_opt = CONTEXT.lock()?;
                let context = context_opt
                    .as_mut()
                    .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
                let mut session = context.open_session(runtime_manager_uuid)?;
                session.invoke_command(RuntimeManagerOpcode::PopulateCertificates as u32, &mut operation)?;
            }

            Ok(Self {
                runtime_manager_uuid: RUNTIME_MANAGER_UUID.to_string(),
            })
        }

        fn plaintext_data(&self, data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError> {
            let parsed = transport_protocol::parse_runtime_manager_request(&data)?;

            unreachable!("Unimplemented");
        }

        fn new_tls_session(&self) -> Result<u32, VeracruzServerError> {
            let mut context_opt = CONTEXT.lock()?;
            let context = context_opt
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;

            let runtime_manager_uuid = Uuid::parse_str(&self.runtime_manager_uuid)?;
            let mut session = context.open_session(runtime_manager_uuid)?;

            let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
            let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

            session.invoke_command(RuntimeManagerOpcode::NewTLSSession as u32, &mut operation)?;

            let session_id = operation.parameters().0.a();

            Ok(session_id)
        }

        fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
            let mut context_opt = CONTEXT.lock()?;
            let context = context_opt
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
            let runtime_manager_uuid = Uuid::parse_str(&self.runtime_manager_uuid)?;
            let mut session = context.open_session(runtime_manager_uuid)?;
            let p0 = ParamValue::new(session_id, 0, ParamType::ValueInput);
            let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
            session.invoke_command(RuntimeManagerOpcode::CloseTLSSession as u32, &mut operation)?;
            Ok(())
        }

        fn tls_data(
            &mut self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            let mut context_opt = CONTEXT.lock()?;
            let context = context_opt
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
            let runtime_manager_uuid = Uuid::parse_str(&self.runtime_manager_uuid)?;
            let mut session = context.open_session(runtime_manager_uuid)?;

            {
                let p0 = ParamValue::new(session_id, 0, ParamType::ValueInput);
                let p1 = ParamTmpRef::new_input(&input);
                let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
                session.invoke_command(RuntimeManagerOpcode::SendTLSData as u32, &mut operation)?;
            }

            let mut active_flag = true;
            let mut ret_array = Vec::new();
            while self.tls_data_needed(session_id, &mut session)? {
                let output_size: usize = 100000; // set to ridiculous long length. TODO: Fix this
                let mut output = vec![0; output_size];

                let p0 = ParamValue::new(session_id, 0, ParamType::ValueInout);
                let p1 = ParamTmpRef::new_output(&mut output);
                let p2 = ParamValue::new(0, 0, ParamType::ValueInout);
                let active = ParamValue::new(1, 0, ParamType::ValueInout);
                let mut operation = Operation::new(0, p0, p1, p2, active);

                session.invoke_command(RuntimeManagerOpcode::GetTLSData as u32, &mut operation)?;
                let output_len = operation.parameters().2.a() as usize;
                active_flag = operation.parameters().3.a() != 0;
                ret_array.push(output[0..output_len].to_vec());
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
            let mut context_guard = CONTEXT.lock()?;
            let runtime_manager_uuid = Uuid::parse_str(&self.runtime_manager_uuid)?;
            match &mut *context_guard {
                None => {
                    return Err(VeracruzServerError::UninitializedEnclaveError);
                }
                Some(context) => {
                    let mut session = context.open_session(runtime_manager_uuid)?;
                    let mut null_operation =
                        Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);
                    session.invoke_command(RuntimeManagerOpcode::ResetEnclave as u32, &mut null_operation)?;
                }
            }

            Ok(true)
        }
    }

    impl Drop for VeracruzServerTZ {
        fn drop(&mut self) {
            match self.close() {
                // We can only panic here since drop function cannot return.
                Err(err) => panic!("VeracruzServerTZ::drop failed in call to self.close:{:?}", err),
                _ => (),
            }
        }
    }

    impl VeracruzServerTZ {
        fn tls_data_needed(
            &self,
            session_id: u32,
            session: &mut Session,
        ) -> Result<bool, VeracruzServerError> {
            let p0 = ParamValue::new(session_id, 0, ParamType::ValueInout);
            let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
            session.invoke_command(RuntimeManagerOpcode::GetTLSDataNeeded as u32, &mut operation)?;
            Ok(operation.parameters().0.b() == 1)
        }

        fn native_attestation(
            proxy_attestation_server_url: &String,
            trustzone_root_enclave_uuid: Uuid,
            runtime_manager_hash: &String,
        ) -> Result<(), VeracruzServerError> {
            let mut context_opt = CONTEXT.lock()?;
            let context = context_opt
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
            let mut trustzone_root_enclave_session = context.open_session(trustzone_root_enclave_uuid)?;

            let firmware_version = VeracruzServerTZ::fetch_firmware_version(&mut trustzone_root_enclave_session)?;

            {
                let runtime_manager_hash_vec = hex::decode(runtime_manager_hash.as_str())?;
                let p0 = ParamTmpRef::new_input(&runtime_manager_hash_vec);
                let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
                trustzone_root_enclave_session
                    .invoke_command(TrustZoneRootEnclaveOpcode::SetRuntimeManagerHashHack as u32, &mut operation)?;
            }
            let (challenge, device_id) =
                VeracruzServerTZ::send_start(proxy_attestation_server_url, "psa", &firmware_version)?;

            let p0 = ParamValue::new(device_id.try_into()?, 0, ParamType::ValueInout);
            let p1 = ParamTmpRef::new_input(&challenge);
            let mut token: Vec<u8> = vec![0; 1024]; //Vec::with_capacity(1024); // TODO: Don't do this
            let p2 = ParamTmpRef::new_output(&mut token);
            let mut csr: Vec<u8> = Vec::with_capacity(2048); // TODO: Don't do this
            let p3 = ParamTmpRef::new_output(&mut csr);
            let mut na_operation = Operation::new(0, p0, p1, p2, p3);
            trustzone_root_enclave_session
                .invoke_command(TrustZoneRootEnclaveOpcode::NativeAttestation as u32, &mut na_operation)?;
            let token_size = na_operation.parameters().0.a();
            let csr_size = na_operation.parameters().0.b();
            unsafe { token.set_len(token_size as usize) };
            unsafe { csr.set_len(csr_size as usize) };

            let (root_enclave_certificate, root_certificate) = VeracruzServerTZ::post_native_psa_attestation_token(proxy_attestation_server_url, &token, &csr, device_id)?;

            let p0 = ParamTmpRef::new_input(&root_certificate);
            let p1 = ParamTmpRef::new_input(&root_enclave_certificate);
            let mut cc_operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
            trustzone_root_enclave_session
                .invoke_command(TrustZoneRootEnclaveOpcode::CertificateChain as u32, &mut cc_operation)
                .map_err(|err| {
                    println!("VeracruzServerTZ::native_attestation call to CertificateChain on root enclave failed:{:?}", err);
                    err
                })?;

            debug!("veracruz_server_tz::native_attestation returning Ok");
            return Ok(());
        }

        fn start_local_attestation(trustzone_root_enclave_uuid: Uuid) -> Result<(Vec<u8>, u32), VeracruzServerError> {
            let mut context_opt = CONTEXT.lock()?;
            let context = context_opt
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
            let mut trustzone_root_enclave_session = context.open_session(trustzone_root_enclave_uuid)?;

            let mut challenge = vec![0; 16];
            let p0 = ParamTmpRef::new_output(&mut challenge);
            let p1 = ParamValue::new(0, 0, ParamType::ValueOutput);
            let mut sla_operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
            trustzone_root_enclave_session
                .invoke_command(TrustZoneRootEnclaveOpcode::StartLocalAttestation as u32, &mut sla_operation)?;
            let challenge_id: u32 = sla_operation.parameters().1.a();
            return Ok((challenge, challenge_id));
        }

        fn post_native_psa_attestation_token(
            proxy_attestation_server_url: &String,
            token: &Vec<u8>,
            csr: &Vec<u8>,
            device_id: i32,
        ) -> Result<(Vec<u8>, Vec<u8>), VeracruzServerError> {
            debug!("veracruz_server_tz::post_psa_attestation_token started");
            let proxy_attestation_server_request =
                transport_protocol::serialize_native_psa_attestation_token(token, csr, device_id)?;
            let encoded_str = base64::encode(&proxy_attestation_server_request);
            let url = format!("{:}/PSA/AttestationToken", proxy_attestation_server_url);
            let response = crate::post_buffer(&url, &encoded_str)?;

            debug!(
                "veracruz_server_tz::post_psa_attestation_token received buffer:{:?}",
                response
            );
            let body_vec =
                base64::decode(&response)?;
            let pasr = transport_protocol::parse_proxy_attestation_server_response(&body_vec).map_err(|err| VeracruzServerError::TransportProtocolError(err))?;
            let cert_chain = pasr.get_cert_chain();
            let root_certificate = cert_chain.get_root_cert();
            let root_enclave_certificate = cert_chain.get_enclave_cert();

            // Pull data out of response buffer
            return Ok((root_enclave_certificate.to_vec(), root_certificate.to_vec()));
        }

        fn fetch_firmware_version(session: &mut Session) -> Result<String, VeracruzServerError> {
            let firmware_version_len = {
                let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
                let mut gfvl_op = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
                session
                    .invoke_command(TrustZoneRootEnclaveOpcode::GetFirmwareVersionLen as u32, &mut gfvl_op)?;
                gfvl_op.parameters().0.a()
            };
            let firmware_version: String = {
                let mut fwv_vec = vec![0; firmware_version_len as usize];
                let p0 = ParamTmpRef::new_output(&mut fwv_vec);
                let mut gfv_op = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
                session
                    .invoke_command(TrustZoneRootEnclaveOpcode::GetFirmwareVersion as u32, &mut gfv_op)?;
                String::from_utf8(fwv_vec)?
            };
            return Ok(firmware_version);
        }

        fn send_start(
            url_base: &str,
            protocol: &str,
            firmware_version: &str,
        ) -> Result<(Vec<u8>, i32), VeracruzServerError> {
            let proxy_attestation_server_response = crate::send_proxy_attestation_server_start(url_base, protocol, firmware_version)?;
            if proxy_attestation_server_response.has_psa_attestation_init() {
                let (challenge, device_id) = transport_protocol::parse_psa_attestation_init(
                    proxy_attestation_server_response.get_psa_attestation_init(),
                )?;
                Ok((challenge, device_id))
            } else {
                Err(VeracruzServerError::MissingFieldError(
                    "proxy_attestation_server_response psa_attestation_init",
                ))
            }
        }
    }
}
