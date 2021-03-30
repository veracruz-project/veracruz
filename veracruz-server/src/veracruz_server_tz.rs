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

            let trustzone_root_enclave_uuid = Uuid::parse_str(&TRUSTZONE_ROOT_ENCLAVE_UUID.to_string())?;
            {
                let runtime_manager_hash = {
                    match policy.runtime_manager_hash(&Platform::TrustZone) {
                        Ok(hash) => hash,
                        Err(_) => return Err(VeracruzServerError::MissingFieldError("runtime_manager_hash_tz")),
                    }
                };

		if !TRUSTZONE_ROOT_ENCLAVE_INITIALIZED.load(Ordering::SeqCst) {
		    debug!("The SGX root enclave is not initialized.");

		    VeracruzServerTZ::native_attestation(
			&policy.proxy_attestation_server_url(),
			trustzone_root_enclave_uuid,
			&runtime_manager_hash,
		    )?;

		    TRUSTZONE_ROOT_ENCLAVE_INITIALIZED.store(true, Ordering::SeqCst);
		}
            }

            let runtime_manager_uuid = Uuid::parse_str(&RUNTIME_MANAGER_UUID.to_string())?;
            let p0 = ParamTmpRef::new_input(&policy_json.as_bytes());

            let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

            {
                let mut context_opt = CONTEXT.lock()?;
                let context = context_opt
                    .as_mut()
                    .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
                let mut session = context.open_session(runtime_manager_uuid)?;
                session.invoke_command(RuntimeManagerOpcode::Initialize as u32, &mut operation)?;
            }

            Ok(Self {
                runtime_manager_uuid: RUNTIME_MANAGER_UUID.to_string(),
            })
        }

        fn plaintext_data(&mut self, data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError> {
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
                    "plaintext_data proxy_psa_attestation_toke",
                ))
            }
        }

        // Note: this function will go away
        fn get_enclave_cert(&mut self) -> Result<Vec<u8>, VeracruzServerError> {
            let mut context_opt = CONTEXT.lock()?;
            let context = context_opt
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
            let runtime_manager_uuid = Uuid::parse_str(&self.runtime_manager_uuid)?;
            let mut session = context.open_session(runtime_manager_uuid)?;

            // get the certificate size
            let certificate_len = {
                let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
                let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

                session.invoke_command(RuntimeManagerOpcode::GetEnclaveCertSize as u32, &mut operation)?;
                operation.parameters().0.a()
            };

            let certificate = {
                let mut cert_vec = vec![0; certificate_len as usize];
                let p0 = ParamTmpRef::new_output(&mut cert_vec);
                let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
                session.invoke_command(RuntimeManagerOpcode::GetEnclaveCert as u32, &mut operation)?;
                cert_vec
            };
            Ok(certificate)
        }

        // Note: This function will go away
        fn get_enclave_name(&mut self) -> Result<String, VeracruzServerError> {
            let mut context_opt = CONTEXT.lock()?;
            let context = context_opt
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
            let runtime_manager_uuid = Uuid::parse_str(&self.runtime_manager_uuid)?;
            let mut session = context.open_session(runtime_manager_uuid)?;

            // get the enclave name size
            let name_len = {
                let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
                let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

                session.invoke_command(RuntimeManagerOpcode::GetEnclaveNameSize as u32, &mut operation)?;
                operation.parameters().0.a()
            };
            let name: String = {
                let mut name_vec = vec![0; name_len as usize];
                //let mut name_vec = Vec::with_capacity(name_len as usize);
                let p0 = ParamTmpRef::new_output(&mut name_vec);
                let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
                session.invoke_command(RuntimeManagerOpcode::GetEnclaveName as u32, &mut operation)?;
                String::from_utf8(name_vec)?
            };
            Ok(name)
        }

        fn proxy_psa_attestation_get_token(
            &mut self,
            challenge: Vec<u8>,
        ) -> Result<(Vec<u8>, Vec<u8>, i32), VeracruzServerError> {
            let mut token: Vec<u8> = Vec::with_capacity(2 * 8192); // TODO: Don't do
            let mut pubkey = Vec::with_capacity(256); // TODO: Don't do this

            let mut context_opt = CONTEXT.lock()?;
            let context = context_opt
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
            let runtime_manager_uuid = Uuid::parse_str(&self.runtime_manager_uuid)?;
            let mut session = context.open_session(runtime_manager_uuid)?;

            // Get the token, public key and device_id
            // p0 - challenge input
            // p1 - device_id output
            // p2 - token output
            // p3 - pubkey output
            let p0 = ParamTmpRef::new_input(&challenge);

            let p1 = ParamValue::new(0, 0, ParamType::ValueOutput);

            //let p1 = ParamValue::new(token.capacity() as u32, 0 as u32, ParamType::ValueInout); // a = token_len, b=device_id
            let p2 = ParamTmpRef::new_output(&mut token);
            let p3 = ParamTmpRef::new_output(&mut pubkey);

            let mut operation = Operation::new(0, p0, p1, p2, p3);
            session.invoke_command(RuntimeManagerOpcode::GetPSAAttestationToken as u32, &mut operation)?;

            let (_, p1_output, p2_output, p3_output) = operation.parameters();
            let device_id: i32 = p1_output.a().try_into()?;
            unsafe {
                let token_len = p2_output.updated_size();
                token.set_len(token_len);
            }
            unsafe {
                let pubkey_len = p3_output.updated_size();
                pubkey.set_len(pubkey_len);
            }
            Ok((token, pubkey, device_id))
        }

        fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError> {
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
            let mut public_key: Vec<u8> = Vec::with_capacity(128); // TODO: Don't do this
            let p3 = ParamTmpRef::new_output(&mut public_key);
            let mut na_operation = Operation::new(0, p0, p1, p2, p3);
            trustzone_root_enclave_session
                .invoke_command(TrustZoneRootEnclaveOpcode::NativeAttestation as u32, &mut na_operation)?;
            let token_size = na_operation.parameters().0.b();
            let public_key_size = na_operation.parameters().0.a();
            let token_vec: Vec<u8> = token[0..token_size as usize].to_vec();
            unsafe { public_key.set_len(public_key_size as usize) };

            VeracruzServerTZ::post_native_psa_attestation_token(proxy_attestation_server_url, &token_vec, device_id)?;
            debug!("veracruz_server_tz::native_attestation returning Ok");
            return Ok(());
        }

        fn post_native_psa_attestation_token(
            proxy_attestation_server_url: &String,
            token: &Vec<u8>,
            device_id: i32,
        ) -> Result<(), VeracruzServerError> {
            debug!("veracruz_server_tz::post_psa_attestation_token started");
            let proxy_attestation_server_request =
                transport_protocol::serialize_native_psa_attestation_token(token, device_id)?;
            let encoded_str = base64::encode(&proxy_attestation_server_request);
            let url = format!("{:}/PSA/AttestationToken", proxy_attestation_server_url);
            let response = crate::post_buffer(&url, &encoded_str)?;

            debug!(
                "veracruz_server_tz::post_psa_attestation_token received buffer:{:?}",
                response
            );
            return Ok(());
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
