//! Intel SGX-specific material for Sinaloa
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
pub mod sinaloa_sgx {

    use crate::sinaloa::*;
    use colima;
    use lazy_static::lazy_static;
    use log::{debug, error};
    use mexico_city_bind::{
        mexico_city_close_session_enc, mexico_city_get_enclave_cert_enc,
        mexico_city_get_enclave_cert_len_enc, mexico_city_get_enclave_name_enc,
        mexico_city_get_enclave_name_len_enc, mexico_city_init_session_manager_enc,
        mexico_city_new_session_enc, mexico_city_psa_attestation_get_token_enc,
        mexico_city_tls_get_data_enc, mexico_city_tls_get_data_needed_enc,
        mexico_city_tls_send_data_enc,
    };
    use sgx_types::*;
    use sgx_urts::SgxEnclave;
    use sonora_bind::{
        sonora_finish_local_attest_enc, sonora_get_firmware_version,
        sonora_get_firmware_version_len, sonora_init_remote_attestation_enc,
        sonora_sgx_get_pubkey_report, sonora_sgx_ra_get_ga, sonora_sgx_ra_get_msg3_trusted,
        sonora_sgx_ra_proc_msg2_trusted, sonora_start_local_attest_enc,
    };
    use std::{ffi::CStr, mem};
    use veracruz_utils;

    lazy_static! {
        static ref SONORA: std::sync::Mutex<Option<SgxEnclave>> = std::sync::Mutex::new(None);
    }

    static MC_ENCLAVE_FILE: &'static str = "./target/debug/mexicocity.signed.so";
    static SONORA_ENCLAVE_FILE: &'static str = "./target/debug/sonora.signed.so";

    pub struct SinaloaSGX {
        mc_enclave: SgxEnclave,
    }

    impl SinaloaSGX {
        fn tls_data_needed(&self, session_id: u32) -> Result<bool, SinaloaError> {
            let mut needed: u8 = 4;
            let mut result: u32 = 0;
            let ret = unsafe {
                mexico_city_tls_get_data_needed_enc(
                    self.mc_enclave.geteid(),
                    &mut result,
                    session_id,
                    &mut needed,
                )
            };
            if ret != 0 || result != 0 {
                return Err(SinaloaError::EnclaveCallError(
                    "mexico_city_tls_get_data_needed_enc",
                ));
            }
            return Ok(needed == 1);
        }
    }

    fn start_enclave(library_fn: &str) -> Result<SgxEnclave, SinaloaError> {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;

        let debug = 1;
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };
        let enclave = SgxEnclave::create(
            library_fn,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )?;

        Ok(enclave)
    }

    fn fetch_firmware_version(enclave: &SgxEnclave) -> Result<String, SinaloaError> {
        let mut gfvl_result: u32 = 0;
        let mut fv_length: u64 = 0;
        let gfvl_ret = unsafe {
            sonora_get_firmware_version_len(enclave.geteid(), &mut gfvl_result, &mut fv_length)
        };
        if gfvl_ret != 0 || gfvl_result != 0 {
            return Err(SinaloaError::EnclaveCallError(
                "sonora_get_firmware_version_len",
            ));
        }

        let mut output = Vec::with_capacity(fv_length as usize);
        let p_output = output.as_mut_ptr();

        let mut gfv_result: u32 = 0;
        let gfv_ret = unsafe {
            sonora_get_firmware_version(enclave.geteid(), &mut gfv_result, p_output, fv_length)
        };
        if gfv_ret != 0 || gfv_result != 0 {
            return Err(SinaloaError::EnclaveCallError(
                "sonora_get_firmware_version",
            ));
        }

        unsafe { output.set_len(fv_length as usize) };
        Ok(std::str::from_utf8(&output[..]).unwrap().to_string())
    }

    impl SinaloaSGX {
        fn send_start(
            &mut self,
            url_base: &str,
            protocol: &str,
            firmware_version: &str,
        ) -> Result<(Vec<u8>, i32), SinaloaError> {
            let proxy_attestation_server_response = crate::send_proxy_attestation_server_start(url_base, protocol, firmware_version)?;
            if proxy_attestation_server_response.has_sgx_attestation_init() {
                let attestation_init = proxy_attestation_server_response.get_sgx_attestation_init();
                let (public_key, device_id) = colima::parse_sgx_attestation_init(attestation_init);
                Ok((public_key, device_id))
            } else {
                Err(SinaloaError::MissingFieldError("sgx_attestation_init"))
            }
        }
    }

    impl SinaloaSGX {
        fn send_sgx_msg1(
            &mut self,
            url_base: &str,
            attestation_context: &sgx_ra_context_t,
            msg1: &sgx_ra_msg1_t,
            device_id: i32,
        ) -> Result<(Vec<u8>, sgx_ra_msg2_t), SinaloaError> {
            let serialized_msg1 = colima::serialize_msg1(*attestation_context, msg1, device_id)?;
            let encoded_msg1 = base64::encode(&serialized_msg1);

            let url = format!("{:}/SGX/Msg1", url_base);

            let received_body = crate::post_buffer(&url, &encoded_msg1)?;

            let body_vec = base64::decode(&received_body)?;
            let parsed = colima::parse_proxy_attestation_server_response(&body_vec)?;
            if parsed.has_sgx_attestation_challenge() {
                let (_context, msg2, challenge) = colima::parse_sgx_attestation_challenge(&parsed)?;
                Ok((challenge.to_vec(), msg2))
            } else {
                Err(SinaloaError::MissingFieldError("sgx_attestation_challenge"))
            }
        }
    }

    fn attestation_challenge(
        enclave: &SgxEnclave,
        pubkey_challenge: &Vec<u8>,
        context: &sgx_ra_context_t,
        msg2: &sgx_ra_msg2_t,
    ) -> Result<(sgx_ra_msg3_t, sgx_quote_t, Vec<u8>, sgx_quote_t, Vec<u8>), SinaloaError> {
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
                    *const sonora_bind::_ra_msg2_t,
                    *const sonora_bind::_target_info_t,
                    *mut sonora_bind::_report_t,
                    *mut sonora_bind::_quote_nonce,
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
            >(sonora_sgx_ra_proc_msg2_trusted)
        };
        let bindgen_get_msg3 = unsafe {
            mem::transmute::<
                unsafe extern "C" fn(
                    u64,
                    *mut u32,
                    u32,
                    u32,
                    *mut sonora_bind::_report_t,
                    *mut sonora_bind::_ra_msg3_t,
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
            >(sonora_sgx_ra_get_msg3_trusted)
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
            return Err(SinaloaError::SGXError(proc_msg2_ret));
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
        let mut pubkey_report = sgx_types::sgx_report_t::default();
        let mut gpr_result: u32 = 0;
        let bindgen_target_info_ref = unsafe {
            mem::transmute::<&sgx_types::sgx_target_info_t, &sonora_bind::_target_info_t>(
                &target_info,
            )
        };
        let bindgen_pubkey_report_ref = unsafe {
            mem::transmute::<&mut sgx_types::sgx_report_t, &mut sonora_bind::_report_t>(
                &mut pubkey_report,
            )
        };
        let gpr_ret = unsafe {
            sonora_sgx_get_pubkey_report(
                enclave.geteid(),
                &mut gpr_result,
                pubkey_challenge.as_ptr(),
                pubkey_challenge.len() as u64,
                bindgen_target_info_ref,
                bindgen_pubkey_report_ref,
            )
        };
        if gpr_ret != 0 || gpr_result != 0 {
            return Err(SinaloaError::EnclaveCallError(
                "sonora_sgx_get_pubkey_report",
            ));
        }

        let mut pubkey_quote_size: u32 = 0;
        let cqs_ret = unsafe {
            sgx_calc_quote_size(std::ptr::null() as *const u8, 0, &mut pubkey_quote_size)
        };
        assert!(cqs_ret == sgx_types::sgx_status_t::SGX_SUCCESS);
        //pubkey_quote_size = 10000;

        // TODO: add this to the policy
        let spid = sgx_types::sgx_spid_t {
            id: [
                0x4E, 0xE1, 0x2C, 0xF0, 0x48, 0x00, 0x04, 0x0B, 0xAB, 0x6F, 0xFD, 0xD4, 0x5F, 0xDF,
                0xD9, 0xBF,
            ],
        };

        let mut pubkey_quote_vec = Vec::with_capacity(pubkey_quote_size as usize);
        let p_qe_report: *mut sgx_report_t = std::ptr::null_mut();

        let p_sig_rl: *const sgx_types::uint8_t = std::ptr::null();
        let p_nonce_nul: *const sgx_types::sgx_quote_nonce_t = std::ptr::null();
        let gpq_result = unsafe {
            sgx_get_quote(
                &pubkey_report,
                sgx_types::sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE,
                &spid,
                p_nonce_nul, //std::ptr::null() as *const sgx_types::sgx_quote_nonce_t,
                p_sig_rl,    //std::ptr::null() as *const sgx_types::uint8_t,
                0,
                p_qe_report,
                pubkey_quote_vec.as_mut_ptr() as *mut sgx_types::sgx_quote_t,
                pubkey_quote_size,
            )
        };
        unsafe { pubkey_quote_vec.set_len(pubkey_quote_size as usize) }
        assert!(gpq_result == sgx_types::sgx_status_t::SGX_SUCCESS);

        let pubkey_quote = unsafe { *(pubkey_quote_vec.as_ptr() as *const sgx_types::sgx_quote_t) };

        let pubkey_quote_sig =
            pubkey_quote_vec[std::mem::size_of::<sgx_types::sgx_quote_t>()..].to_vec();

        // TODO: the documentation tells use that we need to free p_msg3.
        // I'm not sure how to do that. Look into https://doc.rust-lang.org/1.30.0/std/ops/trait.Drop.html
        Ok((
            msg3,
            quote,
            sig.to_vec(),
            pubkey_quote,
            pubkey_quote_sig.to_vec(),
        ))
    }

    impl SinaloaSGX {
        fn send_msg3(
            &self,
            url_base: &str,
            attestation_context: &sgx_ra_context_t,
            msg3: &sgx_ra_msg3_t,
            msg3_quote: &sgx_quote_t,
            msg3_sig: &Vec<u8>,
            pubkey_quote: &sgx_quote_t,
            pubkey_quote_sig: &Vec<u8>,
            device_id: i32,
        ) -> Result<(), SinaloaError> {
            let serialized_tokens = colima::serialize_sgx_attestation_tokens(
                *attestation_context,
                msg3,
                msg3_quote,
                msg3_sig,
                pubkey_quote,
                pubkey_quote_sig,
                device_id,
            )?;
            let encoded_tokens = base64::encode(&serialized_tokens);
            let url = format!("{:}/SGX/Msg3", url_base);

            let received_body = crate::post_buffer(&url, &encoded_tokens)?;
            if received_body == "All's well that ends well" {
                Ok(())
            } else {
                Err(SinaloaError::MismatchError {
                    variable: "msg3 received_body",
                    expected: "All's well that ends well".as_bytes().to_vec(),
                    received: received_body.as_bytes().to_vec(),
                })
            }
        }
    }

    impl SinaloaSGX {
        fn native_attestation(
            &mut self,
            sonora_enclave: &SgxEnclave,
            proxy_attestation_server_url: &String,
        ) -> Result<(), SinaloaError> {
            let firmware_version = fetch_firmware_version(sonora_enclave)?;
            let (public_key, device_id) = self.send_start(proxy_attestation_server_url, "sgx", &firmware_version)?;

            let mut ra_context = sgx_ra_context_t::default();

            let mut ira_result: u32 = 0;
            let ira_ret = unsafe {
                sonora_init_remote_attestation_enc(
                    sonora_enclave.geteid(),
                    &mut ira_result,
                    public_key.as_ptr() as *const u8,
                    public_key.len() as u64,
                    device_id,
                    &mut ra_context,
                )
            };
            if ira_ret != 0 || ira_result != 0 {
                return Err(SinaloaError::EnclaveCallError(
                    "sonora_init_remote_attestation_enc",
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
            let bindgen_sonora_get_ga = unsafe {
                mem::transmute::<
                    unsafe extern "C" fn(
                        u64,
                        *mut u32,
                        u32,
                        *mut sonora_bind::_sgx_ec256_public_t,
                    ) -> u32,
                    unsafe extern "C" fn(
                        u64,
                        *mut sgx_types::sgx_status_t,
                        u32,
                        *mut sgx_types::sgx_ec256_public_t,
                    ) -> sgx_types::sgx_status_t,
                >(sonora_sgx_ra_get_ga)
            };
            // </DIRTY_MESS>
            let msg1_ret = unsafe {
                sgx_ra_get_msg1(
                    ra_context,
                    sonora_enclave.geteid(),
                    bindgen_sonora_get_ga,
                    &mut msg1,
                )
            };
            if msg1_ret != sgx_status_t::SGX_SUCCESS {
                return Err(SinaloaError::SGXError(msg1_ret));
            }

            let (challenge, msg2) =
                self.send_sgx_msg1(&proxy_attestation_server_url, &ra_context, &msg1, device_id)?;

            let (msg3, msg3_quote, msg3_sig, pubkey_quote, pubkey_quote_sig) =
                attestation_challenge(&sonora_enclave, &challenge, &ra_context, &msg2)
                    .expect("Attestation challenge failed");
            self.send_msg3(
                proxy_attestation_server_url,
                &ra_context,
                &msg3,
                &msg3_quote,
                &msg3_sig,
                &pubkey_quote,
                &pubkey_quote_sig,
                device_id,
            )?;

            Ok(())
        }
    }

    impl Sinaloa for SinaloaSGX {
        fn new(policy_json: &str) -> Result<Self, SinaloaError> {
            let mc_enclave = start_enclave(MC_ENCLAVE_FILE)?;

            let mut new_sinaloa = SinaloaSGX {
                mc_enclave: mc_enclave,
            };

            let mut result: u32 = 0;
            let ret = unsafe {
                mexico_city_init_session_manager_enc(
                    new_sinaloa.mc_enclave.geteid(),
                    &mut result,
                    policy_json.as_bytes().as_ptr() as *const u8,
                    policy_json.len() as u64,
                )
            };

            let policy = veracruz_utils::VeracruzPolicy::from_json(policy_json)?;

            {
                let mut sonora_option = SONORA.lock()?;
                match *sonora_option {
                    Some(_) => (), // do nothing, we're good
                    None => {
                        let sonora_enclave = start_enclave(SONORA_ENCLAVE_FILE)?;
                        new_sinaloa.native_attestation(&sonora_enclave, &policy.proxy_attestation_server_url())?;
                        *sonora_option = Some(sonora_enclave)
                    }
                }
            }

            if (result == 0) && (ret == 0) {
                Ok(new_sinaloa)
            } else {
                debug!(
                    "mexico_city_init_session_manager_enc result:{:?}, ret:{:?}",
                    result, ret
                );
                Err(SinaloaError::EnclaveCallError("mexico_city_init_session_manager_enc"))
            }
        }

        fn plaintext_data(&self, data: Vec<u8>) -> Result<Option<Vec<u8>>, SinaloaError> {
            let parsed = colima::parse_mexico_city_request(&data)?;

            if parsed.has_request_proxy_psa_attestation_token() {
                let rpat = parsed.get_request_proxy_psa_attestation_token();
                let challenge = colima::parse_request_proxy_psa_attestation_token(rpat);
                let (psa_attestation_token, pubkey, device_id) =
                    self.proxy_psa_attestation_get_token(challenge)?;
                let serialized_pat = colima::serialize_proxy_psa_attestation_token(
                    &psa_attestation_token,
                    &pubkey,
                    device_id,
                )?;
                Ok(Some(serialized_pat))
            } else {
                unreachable!("Unimplemented");
            }
        }

        fn proxy_psa_attestation_get_token(
            &self,
            challenge: Vec<u8>,
        ) -> Result<(Vec<u8>, Vec<u8>, i32), SinaloaError> {
            let mut pagt_result: u32 = 0;
            let mut token = Vec::with_capacity(2 * 8192); // TODO: Don't do this
            let mut token_size: u64 = 0;
            let mut pubkey = Vec::with_capacity(128); // TODO: Don't do this
            let mut pubkey_size: u64 = 0;
            let mut device_id: i32 = 0;
            let pagt_ret = unsafe {
                mexico_city_psa_attestation_get_token_enc(
                    self.mc_enclave.geteid(),
                    &mut pagt_result,
                    challenge.as_ptr() as *const u8,
                    challenge.len() as u64,
                    token.as_mut_ptr() as *mut u8,
                    token.capacity() as u64,
                    &mut token_size,
                    pubkey.as_mut_ptr() as *mut u8,
                    pubkey.capacity() as u64,
                    &mut pubkey_size,
                    &mut device_id,
                )
            };
            if (pagt_ret != 0) || (pagt_result != 0) {
                Err(SinaloaError::EnclaveCallError(
                    "mexico_city_psa_attestation_get_token_enc",
                ))
            } else {
                unsafe { token.set_len(token_size as usize) };
                unsafe { pubkey.set_len(pubkey_size as usize) };
                Ok((token.clone(), pubkey.clone(), device_id))
            }
        }

        // TODO: This function will go away when we use attestation
        fn get_enclave_cert(&self) -> Result<Vec<u8>, SinaloaError> {
            let mut len_result: u32 = 0;
            let mut cert_len: u64 = 0;
            let len_ret = unsafe {
                mexico_city_get_enclave_cert_len_enc(
                    self.mc_enclave.geteid(),
                    &mut len_result,
                    &mut cert_len,
                )
            };
            if (len_ret != 0) || (len_result != 0) {
                return Err(SinaloaError::EnclaveCallError(
                    "mexico_city_get_enclave_cert_len_enc",
                ));
            }
            let output_size: u64 = cert_len;
            let mut output = Vec::with_capacity(output_size as usize);
            let p_output = output.as_mut_ptr();
            let mut output_len: u64 = 0;
            let mut result: u32 = 0;
            let ret = unsafe {
                mexico_city_get_enclave_cert_enc(
                    self.mc_enclave.geteid(),
                    &mut result,
                    p_output,
                    output_size,
                    &mut output_len,
                )
            };
            if (ret != 0) || (result != 0) || (output_len == 0) {
                Err(SinaloaError::EnclaveCallError(
                    "mexico_city_get_enclave_cert_enc",
                ))
            } else {
                unsafe { output.set_len(output_len as usize) };
                Ok(output)
            }
        }

        // TODO: This function will go away when we use attestation
        fn get_enclave_name(&self) -> Result<String, SinaloaError> {
            let mut len_result: u32 = 0;
            let mut name_len: u64 = 0;
            let len_ret = unsafe {
                mexico_city_get_enclave_name_len_enc(
                    self.mc_enclave.geteid(),
                    &mut len_result,
                    &mut name_len,
                )
            };
            if (len_ret != 0) || (len_result != 0) {
                return Err(SinaloaError::EnclaveCallError(
                    "mexico_city_get_enclave_cert_enc",
                ));
            }
            let output_size = name_len;
            let mut output = Vec::with_capacity(output_size as usize);

            let p_output = output.as_mut_ptr();
            let mut result: u32 = 0;
            let ret = unsafe {
                mexico_city_get_enclave_name_enc(
                    self.mc_enclave.geteid(),
                    &mut result,
                    p_output,
                    output_size as u64,
                )
            };
            if (ret != 0) || (result != 0) {
                Err(SinaloaError::EnclaveCallError(
                    "mexico_city_get_enclave_name_enc",
                ))
            } else {
                unsafe { output.set_len(output_size as usize) };
                Ok(std::str::from_utf8(&output[..]).unwrap().to_string())
            }
        }

        fn new_tls_session(&self) -> Result<u32, SinaloaError> {
            let mut session_id: u32 = 0;
            let mut result: u32 = 0;
            let ret = unsafe {
                mexico_city_new_session_enc(self.mc_enclave.geteid(), &mut result, &mut session_id)
            };
            if (ret == 0) && (result == 0) {
                Ok(session_id)
            } else {
                Err(SinaloaError::EnclaveCallError(
                    "mexico_city_new_session_enc",
                ))
            }
        }

        fn close_tls_session(&self, session_id: u32) -> Result<(), SinaloaError> {
            let mut result: u32 = 0;
            let ret = unsafe {
                mexico_city_close_session_enc(self.mc_enclave.geteid(), &mut result, session_id)
            };
            if (ret == 0) && (result == 0) {
                Ok(())
            } else {
                Err(SinaloaError::EnclaveCallError(
                    "mexico_city_close_session_enc",
                ))
            }
        }

        fn tls_data(
            &self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), SinaloaError> {
            let mut ret_code: u32 = 0;
            let ret_val = unsafe {
                mexico_city_tls_send_data_enc(
                    self.mc_enclave.geteid(),
                    &mut ret_code,
                    session_id,
                    input.as_ptr() as *const u8,
                    input.len() as u64,
                )
            };
            if ret_val != 0 || ret_code != 0 {
                return Err(SinaloaError::EnclaveCallError(
                    "mexico_city_tls_send_data_enc",
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
                    mexico_city_tls_get_data_enc(
                        self.mc_enclave.geteid(),
                        &mut get_ret,
                        session_id,
                        p_output,
                        output_size as u64,
                        &mut output_len,
                        &mut alive_flag,
                    )
                };
                if get_ret != 0 || ret != 0 || output_len == 0 {
                    return Err(SinaloaError::EnclaveCallError(
                        "mexico_city_tls_get_data_enc",
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

        fn close(&mut self) -> Result<bool, SinaloaError> {
            //self.mc_enclave.destroy();
            Ok(true)
        }
    }

    #[no_mangle]
    pub extern "C" fn start_local_attest_ocall(
        dh_msg1: &sgx_dh_msg1_t,
        dh_msg2: &mut sgx_dh_msg2_t,
        sonora_session_id: &mut u64,
    ) -> sgx_status_t {
        let mut result: u32 = 0;
        let sonora_option = SONORA.lock().unwrap();
        let bindgen_msg1_ref =
            unsafe { mem::transmute::<&sgx_dh_msg1_t, &sonora_bind::_sgx_dh_msg1_t>(dh_msg1) };
        let bindgen_msg2_ref = unsafe {
            mem::transmute::<&mut sgx_dh_msg2_t, &mut sonora_bind::_sgx_dh_msg2_t>(dh_msg2)
        };
        match &*sonora_option {
            Some(sonora_enclave) => {
                let ret = unsafe {
                    sonora_start_local_attest_enc(
                        sonora_enclave.geteid(),
                        &mut result,
                        bindgen_msg1_ref,
                        bindgen_msg2_ref,
                        sonora_session_id,
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
        challenge: *const u8,
        challenge_size: u64,
        enclave_cert_hash: *const u8,
        enclave_cert_hash_size: u64,
        enclave_name: *const i8,
        enclave_name_size: u64,
        sonora_session_id: u64,
        token: *mut u8,
        token_buf_size: u64,
        token_size: &mut u64,
        p_pubkey: *mut u8,
        pubkey_buf_size: u64,
        p_pubkey_size: *mut u64,
        p_device_id: &mut i32,
    ) -> sgx_status_t {
        let sonora_option = SONORA.lock().unwrap();
        match &*sonora_option {
            Some(sonora_enclave) => {
                let mut result: u32 = 0;
                let bindgen_msg3_ref = unsafe {
                    mem::transmute::<&sgx_dh_msg3_t, &sonora_bind::_sgx_dh_msg3_t>(dh_msg3)
                };
                let ret = unsafe {
                    sonora_finish_local_attest_enc(
                        sonora_enclave.geteid(),
                        &mut result,
                        bindgen_msg3_ref,
                        challenge,
                        challenge_size,
                        enclave_cert_hash,
                        enclave_cert_hash_size,
                        enclave_name,
                        enclave_name_size,
                        sonora_session_id,
                        token,
                        token_buf_size,
                        token_size,
                        p_pubkey,
                        pubkey_buf_size,
                        p_pubkey_size,
                        p_device_id,
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
