//! Arm TrustZone-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "tz")]
pub mod veracruz_server_tz {

    use crate::veracruz_server::*;
    use hex;
    use io_utils::http::{post_buffer, send_proxy_attestation_server_start};
    use lazy_static::lazy_static;
    use log::debug;
    use optee_teec::{
        Context, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session, Uuid,
    };
    use policy_utils::{policy::Policy, Platform};
    use std::{
        convert::TryInto,
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        },
    };
    use veracruz_utils::{
        platform::tz::{
            runtime_manager_opcode::{RuntimeManagerOpcode, RUNTIME_MANAGER_UUID}
        },
    };

    lazy_static! {
        static ref CONTEXT: Mutex<Option<Context>> = Mutex::new(Some(Context::new().unwrap()));
    }

    pub struct VeracruzServerTZ {
        runtime_manager_uuid: String,
    }

    impl VeracruzServer for VeracruzServerTZ {
        fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
            let policy: Policy = Policy::from_json(policy_json)?;

            let runtime_manager_uuid = Uuid::parse_str(&RUNTIME_MANAGER_UUID.to_string())?;
            let p0 = ParamTmpRef::new_input(&policy_json.as_bytes());

            let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
            let mut context_opt = CONTEXT.lock()?;
            let context = context_opt
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
            let mut session = context.open_session(runtime_manager_uuid)?;
            session.invoke_command(RuntimeManagerOpcode::Initialize as u32, &mut operation)?;

            let (challenge, device_id) =
                VeracruzServerTZ::send_start(policy.proxy_attestation_server_url(), "psa", &"0.0")?;

            let p0 = ParamValue::new(device_id.try_into()?, 0, ParamType::ValueInout);
            let p1 = ParamTmpRef::new_input(&challenge);
            let mut token: Vec<u8> = vec![0; 1024]; // TODO: Don't do this
            let p2 = ParamTmpRef::new_output(&mut token);
            let mut csr: Vec<u8> = Vec::with_capacity(2048); // TODO: Don't do this
            let p3 = ParamTmpRef::new_output(&mut csr);
            let mut attest_operation = Operation::new(0, p0, p1, p2, p3);
            session
                .invoke_command(RuntimeManagerOpcode::Attestation as u32, &mut attest_operation)?;
            let token_size = attest_operation.parameters().0.a();
            let csr_size = attest_operation.parameters().0.b();
            unsafe { token.set_len(token_size as usize) };
            unsafe { csr.set_len(csr_size as usize) };

            let (compute_enclave_certificate, root_certificate) = VeracruzServerTZ::post_native_psa_attestation_token(policy.proxy_attestation_server_url(), &token, &csr, device_id)?;

            let p0 = ParamTmpRef::new_input(&root_certificate);
            let p1 = ParamTmpRef::new_input(&compute_enclave_certificate);
            let mut cc_operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
            session
                .invoke_command(RuntimeManagerOpcode::CertificateChain as u32, &mut cc_operation)
                .map_err(|err| {
                    println!("VeracruzServerTZ::native_attestation call to CertificateChain on compute enclave failed:{:?}", err);
                    err
                })?;

            return Ok(Self {
                runtime_manager_uuid: RUNTIME_MANAGER_UUID.to_string(),
            });
        }

        fn plaintext_data(
            &mut self,
            data: Vec<u8>,
        ) -> Result<Option<Vec<u8>>, VeracruzServerError> {
            let parsed = transport_protocol::parse_runtime_manager_request(&data)?;

            unreachable!("Unimplemented");
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
                    session.invoke_command(
                        RuntimeManagerOpcode::ResetEnclave as u32,
                        &mut null_operation,
                    )?;
                }
            }

            Ok(true)
        }
    }

    impl Drop for VeracruzServerTZ {
        fn drop(&mut self) {
            match self.close() {
                // We can only panic here since drop function cannot return.
                Err(err) => panic!(
                    "VeracruzServerTZ::drop failed in call to self.close:{:?}",
                    err
                ),
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
            session.invoke_command(
                RuntimeManagerOpcode::GetTLSDataNeeded as u32,
                &mut operation,
            )?;
            Ok(operation.parameters().0.b() == 1)
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
            let response =
                post_buffer(&url, &encoded_str).map_err(VeracruzServerError::HttpError)?;

            debug!(
                "veracruz_server_tz::post_psa_attestation_token received buffer:{:?}",
                response
            );
            let body_vec = base64::decode(&response)?;
            let pasr = transport_protocol::parse_proxy_attestation_server_response(&body_vec)
                .map_err(|err| VeracruzServerError::TransportProtocolError(err))?;
            let cert_chain = pasr.get_cert_chain();
            let root_certificate = cert_chain.get_root_cert();
            let root_enclave_certificate = cert_chain.get_enclave_cert();

            // Pull data out of response buffer
            return Ok((root_enclave_certificate.to_vec(), root_certificate.to_vec()));
        }

        fn send_start(
            url_base: &str,
            protocol: &str,
            firmware_version: &str,
        ) -> Result<(Vec<u8>, i32), VeracruzServerError> {
            let (device_id, challenge) = send_proxy_attestation_server_start(url_base, protocol, firmware_version)
                .map_err(|err| VeracruzServerError::HttpError(err))?;
            return Ok((challenge, device_id));
        }
    }
}
