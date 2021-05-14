//! Intel SGX-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "sgx")]
pub mod veracruz_server_sgx {

    use crate::veracruz_server::*;
    use transport_protocol;
    use lazy_static::lazy_static;
    use log::{debug, error};
    use runtime_manager_bind::{
        runtime_manager_close_session_enc, runtime_manager_init_session_manager_enc,
        runtime_manager_new_session_enc, runtime_manager_tls_get_data_enc,
        runtime_manager_tls_get_data_needed_enc, runtime_manager_tls_send_data_enc,
    };
    use sgx_types::*;
    use sgx_urts::SgxEnclave;
    use sgx_root_enclave_bind::{
        sgx_root_enclave_get_firmware_version, sgx_root_enclave_get_firmware_version_len,
        sgx_root_enclave_init_remote_attestation_enc, sgx_root_enclave_sgx_ra_get_ga,
        sgx_root_enclave_sgx_ra_get_msg3_trusted, sgx_root_enclave_sgx_ra_proc_msg2_trusted,
        sgx_root_enclave_start_local_attest_enc, sgx_root_enclave_sgx_get_collateral_report,
        sgx_root_enclave_sgx_send_cert_chain, sgx_root_enclave_finish_local_attest_enc,
    };
    use std::{ffi::CStr, mem};
    use std::io::Write;
    use tempfile;
    use veracruz_utils::policy::policy::Policy;

    lazy_static! {
        static ref SGX_ROOT_ENCLAVE: std::sync::Mutex<Option<SgxEnclave>> = std::sync::Mutex::new(None);
    }

    static RUNTIME_MANAGER_BINARY: &'static [u8] = include_bytes!(
        "../../runtime-manager-bind/target/debug/runtime_manager.signed.so"
    );
    static SGX_ROOT_ENCLAVE_BINARY: &'static [u8] = include_bytes!(
        "../../sgx-root-enclave-bind/target/debug/sgx_root_enclave.signed.so"
    );

    pub struct VeracruzServerSGX {
        runtime_manager_enclave: SgxEnclave,
    }

    impl VeracruzServerSGX {
        fn tls_data_needed(&self, session_id: u32) -> Result<bool, VeracruzServerError> {
            let mut needed: u8 = 4;
            let mut result: u32 = 0;
            let ret = unsafe {
                runtime_manager_tls_get_data_needed_enc(
                    self.runtime_manager_enclave.geteid(),
                    &mut result,
                    session_id,
                    &mut needed,
                )
            };
            if ret != 0 || result != 0 {
                return Err(VeracruzServerError::EnclaveCallError(
                    "runtime_manager_tls_get_data_needed_enc",
                ));
            }
            return Ok(needed == 1);
        }
    }

    fn start_enclave(library_binary: &[u8]) -> Result<SgxEnclave, VeracruzServerError> {
        // need enclave binary as a file, so store in temporary file
        let mut library_file = tempfile::NamedTempFile::new()?;
        library_file.write_all(library_binary)?;
        let library_path = library_file.path();

        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;

        let debug = 1;
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };
        let enclave = SgxEnclave::create(
            library_path,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )?;

        Ok(enclave)
    }

    fn fetch_firmware_version(enclave: &SgxEnclave) -> Result<String, VeracruzServerError> {
        let mut gfvl_result: u32 = 0;
        let mut fv_length: u64 = 0;
        let gfvl_ret = unsafe {
            sgx_root_enclave_get_firmware_version_len(enclave.geteid(), &mut gfvl_result, &mut fv_length)
        };
        if gfvl_ret != 0 || gfvl_result != 0 {
            return Err(VeracruzServerError::EnclaveCallError(
                "sgx_root_enclave_get_firmware_version_len",
            ));
        }

        let mut output = Vec::with_capacity(fv_length as usize);
        let p_output = output.as_mut_ptr();

        let mut gfv_result: u32 = 0;
        let gfv_ret = unsafe {
            sgx_root_enclave_get_firmware_version(enclave.geteid(), &mut gfv_result, p_output, fv_length)
        };
        if gfv_ret != 0 || gfv_result != 0 {
            return Err(VeracruzServerError::EnclaveCallError(
                "sgx_root_enclave_get_firmware_version",
            ));
        }

        unsafe { output.set_len(fv_length as usize) };
        Ok(std::str::from_utf8(&output[..]).unwrap().to_string())
    }

    impl VeracruzServerSGX {
        fn send_start(
            &mut self,
            url_base: &str,
            protocol: &str,
            firmware_version: &str,
        ) -> Result<(Vec<u8>, i32), VeracruzServerError> {
            let proxy_attestation_server_response = crate::send_proxy_attestation_server_start(url_base, protocol, firmware_version)?;
            if proxy_attestation_server_response.has_sgx_attestation_init() {
                let attestation_init = proxy_attestation_server_response.get_sgx_attestation_init();
                let (public_key, device_id) = transport_protocol::parse_sgx_attestation_init(attestation_init);
                Ok((public_key, device_id))
            } else {
                Err(VeracruzServerError::MissingFieldError("sgx_attestation_init"))
            }
        }
    }

    impl VeracruzServerSGX {
        fn send_sgx_msg1(
            &mut self,
            url_base: &str,
            attestation_context: &sgx_ra_context_t,
            msg1: &sgx_ra_msg1_t,
            device_id: i32,
        ) -> Result<(Vec<u8>, sgx_ra_msg2_t), VeracruzServerError> {
            let serialized_msg1 = transport_protocol::serialize_msg1(*attestation_context, msg1, device_id)?;
            let encoded_msg1 = base64::encode(&serialized_msg1);

            let url = format!("{:}/SGX/Msg1", url_base);

            let received_body = crate::post_buffer(&url, &encoded_msg1)?;

            let body_vec = base64::decode(&received_body)?;
            let parsed = transport_protocol::parse_proxy_attestation_server_response(&body_vec)?;
            if parsed.has_sgx_attestation_challenge() {
                let (_context, msg2, challenge) = transport_protocol::parse_sgx_attestation_challenge(&parsed)?;
                Ok((challenge.to_vec(), msg2))
            } else {
                Err(VeracruzServerError::MissingFieldError("sgx_attestation_challenge"))
            }
        }
    }

    fn attestation_challenge(
        enclave: &SgxEnclave,
        collateral_challenge: &Vec<u8>,
        context: &sgx_ra_context_t,
        msg2: &sgx_ra_msg2_t,
    ) -> Result<(sgx_ra_msg3_t, sgx_quote_t, Vec<u8>, sgx_quote_t, Vec<u8>, Vec<u8>), VeracruzServerError> {
        let mut p_msg3 = std::ptr::null_mut();
        let mut msg3_size = 0;
        let msg2_size: u32 = std::mem::size_of::<sgx_ra_msg2_t>() as u32;

        // <DIRTY_MESS>
        // This DIRTY_MESS is necessary because bindgen sort of mangles the
        // return type of functions that return enums. Instead of returning
        // an enum, the function now returns a u32. This means that the
        // function signatures no longer match what sgx_ra_proc_msg2 requires.
        // By "transmuting" the functions, this should "solve" the problem.
        // Notice that this is unsafe, and might blow up in my face
        let bindgen_proc_msg2 = unsafe {
            mem::transmute::<
                unsafe extern "C" fn(
                    u64,
                    *mut u32,
                    u32,
                    *const sgx_root_enclave_bind::_ra_msg2_t,
                    *const sgx_root_enclave_bind::_target_info_t,
                    *mut sgx_root_enclave_bind::_report_t,
                    *mut sgx_root_enclave_bind::_quote_nonce,
                ) -> u32,
                unsafe extern "C" fn(
                    u64,
                    *mut sgx_types::sgx_status_t,
                    u32,
                    *const sgx_types::sgx_ra_msg2_t,
                    *const sgx_types::sgx_target_info_t,
                    *mut sgx_types::sgx_report_t,
                    *mut sgx_types::sgx_quote_nonce_t,
                ) -> sgx_types::sgx_status_t,
            >(sgx_root_enclave_sgx_ra_proc_msg2_trusted)
        };
        let bindgen_get_msg3 = unsafe {
            mem::transmute::<
                unsafe extern "C" fn(
                    u64,
                    *mut u32,
                    u32,
                    u32,
                    *mut sgx_root_enclave_bind::_report_t,
                    *mut sgx_root_enclave_bind::_ra_msg3_t,
                    u32,
                ) -> u32,
                unsafe extern "C" fn(
                    u64,
                    *mut sgx_types::sgx_status_t,
                    u32,
                    u32,
                    *mut sgx_types::sgx_report_t,
                    *mut sgx_types::sgx_ra_msg3_t,
                    u32,
                ) -> sgx_types::sgx_status_t,
            >(sgx_root_enclave_sgx_ra_get_msg3_trusted)
        };
        // </DIRTY_MESS>
        let proc_msg2_ret = unsafe {
            sgx_ra_proc_msg2(
                *context,
                enclave.geteid(),
                bindgen_proc_msg2,
                bindgen_get_msg3,
                msg2,
                msg2_size,
                &mut p_msg3,
                &mut msg3_size,
            )
        };

        let p_msg3_byte = p_msg3 as *mut u8;
        if proc_msg2_ret != sgx_types::sgx_status_t::SGX_SUCCESS {
            debug!("proc_msg2_ret:{:?}", proc_msg2_ret);
            return Err(VeracruzServerError::SGXError(proc_msg2_ret));
        }

        let msg3 = unsafe { *p_msg3 as sgx_ra_msg3_t };
        let quote_offset = std::mem::size_of::<sgx_ra_msg3_t>();
        let p_quote = unsafe { p_msg3_byte.offset(quote_offset as isize) as *mut sgx_quote_t };
        let quote = unsafe { *p_quote };

        let sig_offset = std::mem::size_of::<sgx_quote_t>();
        let sig_size = msg3_size as usize - quote_offset - sig_offset;

        let p_sig = unsafe { p_quote.offset(1) as *mut u8 };

        let sig = unsafe { std::slice::from_raw_parts_mut(p_sig, sig_size) };

        // initialize the quote (not sure what this does or what to do with the output)
        let mut target_info = sgx_types::sgx_target_info_t::default();
        let mut gid = sgx_types::sgx_epid_group_id_t::default();
        let siq_ret = unsafe { sgx_init_quote(&mut target_info, &mut gid) };
        assert!(siq_ret == sgx_types::sgx_status_t::SGX_SUCCESS);

        // get the public key report
        let mut collateral_report = sgx_types::sgx_report_t::default();
        let mut gpr_result: u32 = 0;
        let bindgen_target_info_ref = unsafe {
            mem::transmute::<&sgx_types::sgx_target_info_t, &sgx_root_enclave_bind::_target_info_t>(
                &target_info,
            )
        };
        let bindgen_collateral_report_ref = unsafe {
            mem::transmute::<&mut sgx_types::sgx_report_t, &mut sgx_root_enclave_bind::_report_t>(
                &mut collateral_report,
            )
        };

        let mut csr: Vec<u8> = Vec::with_capacity(1024);
        let csr_buf_size = csr.capacity();
        let mut csr_size: u64 = 0;

        let gpr_ret = unsafe {
            sgx_root_enclave_sgx_get_collateral_report(
                enclave.geteid(),
                &mut gpr_result,
                collateral_challenge.as_ptr(),
                collateral_challenge.len() as u64,
                bindgen_target_info_ref,
                bindgen_collateral_report_ref,
                csr.as_mut_ptr() as *mut u8,
                csr_buf_size as u64,
                &mut csr_size,
            )
        };
        if gpr_ret != 0 || gpr_result != 0 {
            return Err(VeracruzServerError::EnclaveCallError(
                "sgx_root_enclave_sgx_get_collateral_report",
            ));
        }

        unsafe { csr.set_len(csr_size as usize) };

        let mut collateral_quote_size: u32 = 0;
        let cqs_ret = unsafe {
            sgx_calc_quote_size(std::ptr::null() as *const u8, 0, &mut collateral_quote_size)
        };
        assert!(cqs_ret == sgx_types::sgx_status_t::SGX_SUCCESS);

        // TODO: add this to the policy
        let spid = sgx_types::sgx_spid_t {
            id: [
                0x4E, 0xE1, 0x2C, 0xF0, 0x48, 0x00, 0x04, 0x0B, 0xAB, 0x6F, 0xFD, 0xD4, 0x5F, 0xDF,
                0xD9, 0xBF,
            ],
        };

        let mut collateral_quote_vec = Vec::with_capacity(collateral_quote_size as usize);
        let p_qe_report: *mut sgx_report_t = std::ptr::null_mut();

        let p_sig_rl: *const sgx_types::uint8_t = std::ptr::null();
        let p_nonce_nul: *const sgx_types::sgx_quote_nonce_t = std::ptr::null();
        let gpq_result = unsafe {
            sgx_get_quote(
                &collateral_report,
                sgx_types::sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE,
                &spid,
                p_nonce_nul,
                p_sig_rl,
                0,
                p_qe_report,
                collateral_quote_vec.as_mut_ptr() as *mut sgx_types::sgx_quote_t,
                collateral_quote_size,
            )
        };
        unsafe { collateral_quote_vec.set_len(collateral_quote_size as usize) }
        assert!(gpq_result == sgx_types::sgx_status_t::SGX_SUCCESS);

        let collateral_quote = unsafe { *(collateral_quote_vec.as_ptr() as *const sgx_types::sgx_quote_t) };

        let collateral_quote_sig =
            collateral_quote_vec[std::mem::size_of::<sgx_types::sgx_quote_t>()..].to_vec();

        // TODO: the documentation tells use that we need to free p_msg3.
        // I'm not sure how to do that. Look into https://doc.rust-lang.org/1.30.0/std/ops/trait.Drop.html
        Ok((
            msg3,
            quote,
            sig.to_vec(),
            collateral_quote,
            collateral_quote_sig.to_vec(),
            csr
        ))
    }

    impl VeracruzServerSGX {
        fn send_msg3(
            &self,
            url_base: &str,
            attestation_context: &sgx_ra_context_t,
            msg3: &sgx_ra_msg3_t,
            msg3_quote: &sgx_quote_t,
            msg3_sig: &Vec<u8>,
            collateral_quote: &sgx_quote_t,
            collateral_quote_sig: &Vec<u8>,
            device_id: i32,
            csr: &Vec<u8>
        ) -> Result<(Vec<u8>, Vec<u8>), VeracruzServerError> {
            let serialized_tokens = transport_protocol::serialize_sgx_attestation_tokens(
                *attestation_context,
                msg3,
                msg3_quote,
                msg3_sig,
                collateral_quote,
                collateral_quote_sig,
                csr,
                device_id,
            )?;
            let encoded_tokens = base64::encode(&serialized_tokens);
            let url = format!("{:}/SGX/Msg3", url_base);

            let received_body = crate::post_buffer(&url, &encoded_tokens)?;
            let received_bytes = base64::decode(&received_body).unwrap();
            let parsed = transport_protocol::parse_proxy_attestation_server_response(&received_bytes)?;
            if parsed.has_cert_chain() {
                let (root_cert, enclave_cert) = transport_protocol::parse_cert_chain(&parsed.get_cert_chain());
                return Ok((root_cert, enclave_cert));
            } else {
                return Err(VeracruzServerError::MissingFieldError("cert_chain"));
            }
        }
    }

    impl VeracruzServerSGX {
        fn native_attestation(
            &mut self,
            sgx_root_enclave: &SgxEnclave,
            proxy_attestation_server_url: &String,
        ) -> Result<(), VeracruzServerError> {
            let firmware_version = fetch_firmware_version(sgx_root_enclave)?;
            let (public_key, device_id) = self.send_start(proxy_attestation_server_url, "sgx", &firmware_version)?;

            let mut ra_context = sgx_ra_context_t::default();

            let mut ira_result: u32 = 0;
            let ira_ret = unsafe {
                sgx_root_enclave_init_remote_attestation_enc(
                    sgx_root_enclave.geteid(),
                    &mut ira_result,
                    public_key.as_ptr() as *const u8,
                    public_key.len() as u64,
                    &mut ra_context,
                )
            };
            if ira_ret != 0 || ira_result != 0 {
                return Err(VeracruzServerError::EnclaveCallError(
                    "sgx_root_enclave_init_remote_attestation_enc",
                ));
            }

            let mut msg1 = sgx_ra_msg1_t::default();
            // <DIRTY_MESS>
            // This DIRTY_MESS is necessary because bindgen sort of mangles the
            // return type of functions that return enums. Instead of returning
            // an enum, the function now returns a u32. This means that the
            // function signatures no longer match what sgx_ra_get_msg1 requires.
            // By "transmuting" the function, this should "solve" the problem.
            // Notice that this is unsafe, and might blow up in my face
            let bindgen_sgx_root_enclave_get_ga = unsafe {
                mem::transmute::<
                    unsafe extern "C" fn(
                        u64,
                        *mut u32,
                        u32,
                        *mut sgx_root_enclave_bind::_sgx_ec256_public_t,
                    ) -> u32,
                    unsafe extern "C" fn(
                        u64,
                        *mut sgx_types::sgx_status_t,
                        u32,
                        *mut sgx_types::sgx_ec256_public_t,
                    ) -> sgx_types::sgx_status_t,
                >(sgx_root_enclave_sgx_ra_get_ga)
            };
            // </DIRTY_MESS>
            let msg1_ret = unsafe {
                sgx_ra_get_msg1(
                    ra_context,
                    sgx_root_enclave.geteid(),
                    bindgen_sgx_root_enclave_get_ga,
                    &mut msg1,
                )
            };
            if msg1_ret != sgx_status_t::SGX_SUCCESS {
                return Err(VeracruzServerError::SGXError(msg1_ret));
            }

            let (challenge, msg2) =
                self.send_sgx_msg1(&proxy_attestation_server_url, &ra_context, &msg1, device_id)?;

            let (msg3, msg3_quote, msg3_sig, collateral_quote, collateral_quote_sig, csr) =
                attestation_challenge(&sgx_root_enclave, &challenge, &ra_context, &msg2)
                    .expect("Attestation challenge failed");
            let (root_cert, enclave_cert) = self.send_msg3(
                proxy_attestation_server_url,
                &ra_context,
                &msg3,
                &msg3_quote,
                &msg3_sig,
                &collateral_quote,
                &collateral_quote_sig,
                device_id,
                &csr
            )?;

            let mut gcr_result: u32 = 0;
            let gcr_ret = unsafe {
                sgx_root_enclave_sgx_send_cert_chain(sgx_root_enclave.geteid(),
                                                 &mut gcr_result,
                                                 root_cert.as_ptr(),
                                                 root_cert.len() as u64,
                                                 enclave_cert.as_ptr(),
                                                 enclave_cert.len() as u64)
            };

            if gcr_ret != 0 || gcr_result != 0 {
                return Err(VeracruzServerError::EnclaveCallError(
                    "sgx_root_enclave_sgx_send_cert_chain",
                ));
            }
            Ok(())
        }
    }

    impl VeracruzServer for VeracruzServerSGX {
        fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
            let runtime_manager_enclave = start_enclave(RUNTIME_MANAGER_BINARY)?;

            let mut new_veracruz_server = VeracruzServerSGX {
                runtime_manager_enclave: runtime_manager_enclave,
            };

            let policy = Policy::from_json(policy_json)?;

            // Start the root enclave, if necessary
            {
                let mut sgx_root_enclave = SGX_ROOT_ENCLAVE.lock()?;
                match *sgx_root_enclave {
                    Some(_) => (), // do nothing, we're good
                    None => {
                        let enclave = start_enclave(SGX_ROOT_ENCLAVE_BINARY)?;
                        new_veracruz_server.native_attestation(&enclave, &policy.proxy_attestation_server_url())?;
                        *sgx_root_enclave = Some(enclave)
                    }
                }
            }

            // initialize the compute enclave
            let mut result: u32 = 0;
            let ret = unsafe {
                runtime_manager_init_session_manager_enc(
                    new_veracruz_server.runtime_manager_enclave.geteid(),
                    &mut result,
                    policy_json.as_bytes().as_ptr() as *const u8,
                    policy_json.len() as u64,
                )
            };

            if (result == 0) && (ret == 0) {
                Ok(new_veracruz_server)
            } else {
                debug!(
                    "runtime_manager_init_session_manager_enc result:{:?}, ret:{:?}",
                    result, ret
                );
                Err(VeracruzServerError::EnclaveCallError("runtime_manager_init_session_manager_enc"))
            }
        }

        fn plaintext_data(&self, _data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError> {
                unreachable!("Unimplemented");
        }

        fn new_tls_session(&self) -> Result<u32, VeracruzServerError> {
            let mut session_id: u32 = 0;
            let mut result: u32 = 0;
            let ret = unsafe {
                runtime_manager_new_session_enc(self.runtime_manager_enclave.geteid(), &mut result, &mut session_id)
            };
            if (ret == 0) && (result == 0) {
                Ok(session_id)
            } else {
                Err(VeracruzServerError::EnclaveCallError(
                    "runtime_manager_new_session_enc",
                ))
            }
        }

        fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
            let mut result: u32 = 0;
            let ret = unsafe {
                runtime_manager_close_session_enc(self.runtime_manager_enclave.geteid(), &mut result, session_id)
            };
            if (ret == 0) && (result == 0) {
                Ok(())
            } else {
                Err(VeracruzServerError::EnclaveCallError(
                    "runtime_manager_close_session_enc",
                ))
            }
        }

        fn tls_data(
            &mut self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            let mut ret_code: u32 = 0;
            let ret_val = unsafe {
                runtime_manager_tls_send_data_enc(
                    self.runtime_manager_enclave.geteid(),
                    &mut ret_code,
                    session_id,
                    input.as_ptr() as *const u8,
                    input.len() as u64,
                )
            };
            if ret_val != 0 || ret_code != 0 {
                return Err(VeracruzServerError::EnclaveCallError(
                    "runtime_manager_tls_send_data_enc",
                ));
            }

            let mut ret_array = Vec::new();
            let mut alive_flag: u8 = 1;
            while self.tls_data_needed(session_id)? {
                let mut get_ret: u32 = 0;
                let output_size: usize = 100000; // set to ridiculous long length
                let mut output = Vec::with_capacity(output_size);
                let p_output = output.as_mut_ptr();
                let mut output_len: u64 = 0;
                let ret = unsafe {
                    runtime_manager_tls_get_data_enc(
                        self.runtime_manager_enclave.geteid(),
                        &mut get_ret,
                        session_id,
                        p_output,
                        output_size as u64,
                        &mut output_len,
                        &mut alive_flag,
                    )
                };
                if get_ret != 0 || ret != 0 || output_len == 0 {
                    return Err(VeracruzServerError::EnclaveCallError(
                        "runtime_manager_tls_get_data_enc",
                    ));
                }
                unsafe { output.set_len(output_len as usize) };
                ret_array.push(output);
            }

            Ok((
                alive_flag != 0,
                if ret_array.len() > 0 {
                    Some(ret_array)
                } else {
                    None
                },
            ))
        }

        fn close(&mut self) -> Result<bool, VeracruzServerError> {
            //self.runtime_manager_enclave.destroy();
            Ok(true)
        }
    }

    #[no_mangle]
    pub extern "C" fn start_local_attest_ocall(
        dh_msg1: &sgx_dh_msg1_t,
        dh_msg2: &mut sgx_dh_msg2_t,
        sgx_root_enclave_session_id: &mut u64,
    ) -> sgx_status_t {
        let mut result: u32 = 0;
        let sgx_root_enclave = SGX_ROOT_ENCLAVE.lock().unwrap();
        let bindgen_msg1_ref =
            unsafe { mem::transmute::<&sgx_dh_msg1_t, &sgx_root_enclave_bind::_sgx_dh_msg1_t>(dh_msg1) };
        let bindgen_msg2_ref = unsafe {
            mem::transmute::<&mut sgx_dh_msg2_t, &mut sgx_root_enclave_bind::_sgx_dh_msg2_t>(dh_msg2)
        };
        match &*sgx_root_enclave {
            Some(sgx_root_enclave) => {
                let ret = unsafe {
                    sgx_root_enclave_start_local_attest_enc(
                        sgx_root_enclave.geteid(),
                        &mut result,
                        bindgen_msg1_ref,
                        bindgen_msg2_ref,
                        sgx_root_enclave_session_id,
                    )
                };
                if (ret != 0) || (result != 0) {
                    return sgx_status_t::SGX_ERROR_UNEXPECTED;
                }
            }
            None => {
                assert!(false);
            }
        }
        sgx_status_t::SGX_SUCCESS
    }


    #[no_mangle]
    pub extern "C" fn finish_local_attest_ocall(
        dh_msg3: &sgx_dh_msg3_t,
        csr: *const u8,
        csr_size: u64,
        sgx_root_enclave_session_id: u64,
        cert: *mut u8,
        cert_buf_size: u64,
        cert_size: &mut u64,
        cert_lengths: *mut u32,
        cert_lengths_size: u64,
    ) -> sgx_status_t {
        let sgx_root_enclave = SGX_ROOT_ENCLAVE.lock().unwrap();
        match &*sgx_root_enclave {
            Some(sgx_root_enclave) => {
                let mut result: u32 = 0;
                let bindgen_msg3_ref = unsafe {
                    mem::transmute::<&sgx_dh_msg3_t, &sgx_root_enclave_bind::_sgx_dh_msg3_t>(dh_msg3)
                };
                let ret = unsafe {
                    sgx_root_enclave_finish_local_attest_enc(
                        sgx_root_enclave.geteid(),
                        &mut result,
                        bindgen_msg3_ref,
                        csr,
                        csr_size,
                        sgx_root_enclave_session_id,
                        cert,
                        cert_buf_size,
                        cert_size,
                        cert_lengths,
                        cert_lengths_size,
                    )
                };
                if (ret != 0) || (result != 0) {
                    return sgx_status_t::SGX_ERROR_UNEXPECTED;
                }
            }
            None => {
                assert!(false);
            }
        }
        sgx_status_t::SGX_SUCCESS
    }

    #[no_mangle]
    pub extern "C" fn debug_and_error_output_ocall(
        message: *const c_char,
        code: u32,
    ) -> sgx_status_t {
        let msg = match unsafe { CStr::from_ptr(message).to_str() } {
            Ok(o) => o,
            Err(err) => {
                error!(
                    "Failed to parse the debug or error message, with error message: {:?}",
                    err
                );
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        };
        // it is a debug information
        if code == 0 {
            debug!("Enclave debug message \"{}\"", msg);
        } else {
            error!(
                "Enclave returns error code {} and message \"{}\"",
                code, msg
            );
        }
        sgx_status_t::SGX_SUCCESS
    }
}
