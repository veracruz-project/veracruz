//! Intel SGX Attestation (EPID)-specific material for the Veracruz proxy attestation server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::error::*;
use base64;
use transport_protocol;
use curl::easy::{Easy, List};
use lazy_static::lazy_static;
use openssl;
use percent_encoding;
use rand::Rng;
use serde_json;
use sgx_types::{
    marker::ContiguousMemory, sgx_cmac_128bit_tag_t, sgx_ec256_dh_shared_t, sgx_ec256_private_t,
    sgx_ec256_public_t, sgx_quote_t, sgx_ra_msg1_t, sgx_ra_msg2_t, sgx_ra_msg3_t, sgx_spid_t,
    sgx_status_t,
};
use sgx_ucrypto::{SgxEccHandle, SgxShaHandle};
use std::{collections::HashMap, env, io::Read, sync::Mutex};
use stringreader;

#[derive(Clone)]
pub(crate) struct SgxAttestationContext {
    firmware_version: String,
    private_key: sgx_ec256_private_t,
    public_key: sgx_ec256_public_t,
    smk: Option<sgx_cmac_128bit_tag_t>,
    vk: Option<sgx_cmac_128bit_tag_t>,
    msg1: Option<sgx_ra_msg1_t>,
    msg2: Option<sgx_ra_msg2_t>,
    pubkey_challenge: Option<[u8; 16]>,
}

lazy_static! {
    static ref ATTESTATION_CONTEXT: Mutex<HashMap<i32, SgxAttestationContext>> =
        Mutex::new(HashMap::new());
    static ref TOKEN: String = {
        let value = env::var("IAS_TOKEN").expect("Failed to read IAS_TOKEN environment variable.");
        value
    };
}

static QUOTE_TYPE: u16 = 1; //SAMPLE_QUOTE_LINKABLE_SIGNATURE
                            //static QUOTE_TYPE = 0;      //SAMPLE_QUOTE_UNLINKABLE_SIGNATURE

pub fn start(firmware_version: &str, device_id: i32) -> ProxyAttestationServerResponder {
    let sgx_ecc_handle = SgxEccHandle::new();
    sgx_ecc_handle.open()
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::sgx::start failed to open sgx_ecc_handle:{:?}", err);
            err
        })?;
    let (private_key, public_key) = sgx_ecc_handle.create_key_pair()
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::sgx::start failed to create key pair:{:?}", err);
            err
        })?;
    sgx_ecc_handle.close()
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::sgx::start failed to close sgx_ecc_Handle:{:?}", err);
            err
        })?;

    let mut serialized_pubkey = Vec::new();

    serialized_pubkey.append(&mut public_key.gx.to_vec());
    serialized_pubkey.append(&mut public_key.gy.to_vec());
    {
        let attestation_context = SgxAttestationContext {
            firmware_version: firmware_version.to_string(),
            private_key: private_key,
            public_key: public_key,
            smk: None,
            vk: None,
            msg1: None,
            msg2: None,
            pubkey_challenge: None,
        };
        let mut ac_hash = ATTESTATION_CONTEXT.lock()
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::sgx::start failed to obtain lock on ATTESTATION_CONTEXT:{:?}", err);
                err
            })?;
        ac_hash.insert(device_id, attestation_context);
    }
    let serialized_attestation_init =
        transport_protocol::serialize_sgx_attestation_init(&serialized_pubkey, device_id)
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::sgx::start serialize_sgx_attestation_init failed:{:?}", err);
                err
            })?;
    Ok(base64::encode(&serialized_attestation_init))
}

pub fn msg1(body_string: String) -> ProxyAttestationServerResponder {
    let received_bytes = base64::decode(&body_string)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::sgx::msg1 failed to decode body_string as base64:{:?}", err);
            err
        })?;

    let parsed = transport_protocol::parse_proxy_attestation_server_request(&received_bytes)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::sgx::msg1 failed to parse_proxy_attestation_server_request:{:?}", err);
            err
        })?;
    if !parsed.has_msg1() {
        return Err(ProxyAttestationServerError::MissingFieldError("msg1"));
    }
    let (context, msg1, device_id) = transport_protocol::parse_msg1(&parsed);
    let (msg2, pubkey_challenge) = {
        let mut pubkey_challenge: [u8; 16] = [0; 16];
        let mut rng = rand::thread_rng();

        rng.fill(&mut pubkey_challenge);
        let sgx_ecc_handle = SgxEccHandle::new();
        sgx_ecc_handle.open()
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::sgx::msg1 failed to open sgx_ecc_handle:{:?}", err);
                err
            })?;
        let (private_key, public_key) = {
            let mut ac_hash = ATTESTATION_CONTEXT.lock()
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg1 failed to obtain lock on ATTESTATION_CONTEXT:{:?}", err);
                    err
                })?;

            let attestation_context = ac_hash
                .get_mut(&device_id)
                .ok_or(ProxyAttestationServerError::NoDeviceError(device_id)) 
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg1 NoDeviceError:{:?}", err);
                    err
                })?;
            (
                attestation_context.private_key.clone(),
                attestation_context.public_key.clone(),
            )
        };
        let dh_key = sgx_ecc_handle.compute_shared_dhkey(&private_key, &msg1.g_a)?;
        sgx_ecc_handle.close()
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::sgx::msg1 failed to close sgx_ecc_handle:{:?}", err);
                err
            })?;
        let (smk, vk) = generate_sgx_symmetric_keys(&dh_key)
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::sgx::msg1 generate_sgx_symmetric_keys failed:{:?}", err);
                err
            })?;
        let msg2 = proc_msg1(&msg1, &smk, &private_key, &public_key)
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::sgx::msg1 proc_msg1 failed:{:?}", err);
                err
            })?;
        {
            let mut ac_hash = ATTESTATION_CONTEXT.lock()
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg1 failed to obtain lock on ATTESTATION_CONTEXT:{:?}", err);
                    err
                })?;
            let mut attestation_context = ac_hash
                .get_mut(&device_id)
                .ok_or(ProxyAttestationServerError::NoDeviceError(device_id))
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg1 NoDeviceError:{:?}", err);
                    err
                })?;

            attestation_context.smk = Some(smk);
            attestation_context.vk = Some(vk);
            attestation_context.msg1 = Some(msg1);
            attestation_context.msg2 = Some(msg2);
            attestation_context.pubkey_challenge = Some(pubkey_challenge);
        }
        (msg2, pubkey_challenge)
    };

    let serialized_challenge =
        transport_protocol::serialize_sgx_attestation_challenge(context, &msg2, &pubkey_challenge)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::sgx::msg1 serialize_sgx_attestation_challenge failed:{:?}", err);
            err
        })?;

    Ok(base64::encode(&serialized_challenge))
}

pub fn msg3(body_string: String) -> ProxyAttestationServerResponder {
    let received_bytes = base64::decode(&body_string)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::sgx::msg3 base64 decode ov body_string failed:{:?}", err);
            err
        })?;

    let parsed = transport_protocol::parse_proxy_attestation_server_request(&received_bytes)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::sgx::msg3 parse_proxy_attestation_server_request failed:{:?}", err);
            err
        })?;
    if !parsed.has_sgx_attestation_tokens() {
        println!("received data is incorrect. TODO: Handle this");
        return Err(ProxyAttestationServerError::NoSGXAttestationTokenError);
    }
    let (msg3, msg3_quote, msg3_sig, collateral_quote, collateral_sig, csr, device_id) =
        transport_protocol::parse_attestation_tokens(&parsed)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::sgx::msg3 parse_attestation_tokens failed:{:?}", err);
            err
        })?;
    {
        let attestation_context = {
            let mut ac_hash = ATTESTATION_CONTEXT.lock()
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg3 failed to obtain lock on ATTESTATION_CONTEXT:{:?}", err);
                    err
                })?;
            // we are calling remove because after this, the context will no
            // longer be needed
            let context = ac_hash
                .remove(&device_id)
                .ok_or(ProxyAttestationServerError::NoDeviceError(device_id))
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg3 NoDeviceError:{:?}", err);
                    err
                })?;
            context.clone()
        };

        let expected_enclave_hash = {
            let connection = crate::orm::establish_connection()
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg3 establish_connection failed:{:?}", err);
                    err
                })?;
            crate::orm::get_firmware_version_hash(
                &connection,
                &"sgx".to_string(),
                &attestation_context.firmware_version,
            )
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::sgx::msg3 get_firmware_version_hash failed:{:?}", err);
                err
            })?
            .ok_or(ProxyAttestationServerError::MissingFieldError("firmware version"))
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::sgx::msg3 MissingFieldError:{:?}", err);
                err
            })?
        };

        // TODO: This function call needs to be reworked
        let msg3_epid_pseudonym = authenticate_msg3(
            &attestation_context
                .msg1
                .ok_or(ProxyAttestationServerError::MissingFieldError("attestation_context.msg1"))
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg3 MissingFieldError:{:?}", err);
                    err
                })?,
            &attestation_context
                .msg2
                .ok_or(ProxyAttestationServerError::MissingFieldError("attestation_context.msg2"))
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg3 MissingFieldError:{:?}", err);
                    err
                })?,
            &msg3,
            &msg3_quote,
            &msg3_sig,
            &attestation_context
                .smk
                .ok_or(ProxyAttestationServerError::MissingFieldError("attestation_context.smk"))
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg3 MissingFieldError:{:?}", err);
                    err
                })?,
            &attestation_context
                .vk
                .ok_or(ProxyAttestationServerError::MissingFieldError("attestation_context.vk"))
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg3 MissingFieldError:{:?}", err);
                    err
                })?,
            &expected_enclave_hash,
        )?;

        let (pubkey_epid_pseudonym, collateral_hash) = authenticate_pubkey_quote(
            &attestation_context
                .pubkey_challenge
                .ok_or(ProxyAttestationServerError::MissingFieldError("pubkey_challenge"))
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::sgx::msg3 MissingFieldError:{:?}", err);
                    err
                })?,
            &collateral_quote,
            &collateral_sig,
        )?;

        let calculated_collateral_hash = ring::digest::digest(&ring::digest::SHA256, &csr);
        if calculated_collateral_hash.as_ref().to_vec() != collateral_hash {
            // Something has changed the csr that came along with the token. This is bad.
            return Err(ProxyAttestationServerError::MismatchError {
                variable: "collateral_hash",
                expected: collateral_hash,
                received: calculated_collateral_hash.as_ref().to_vec(),
            });
        }


        if pubkey_epid_pseudonym != msg3_epid_pseudonym {
            // We cannot verify that msg3 and pubkey_quote came from the same SGX system
            return Err(ProxyAttestationServerError::MismatchError {
                variable: "msg3 and pubkey_quote",
                expected: pubkey_epid_pseudonym.into_bytes(),
                received: msg3_epid_pseudonym.into_bytes(),
            });
        }

        // check that the enclave that generated collateral_quote has the same firmware as the enclave that
        // generated msg3
        if msg3_quote.report_body.mr_enclave.m != collateral_quote.report_body.mr_enclave.m {
            // TODO: Even if this is true, does this eman that they are from the same enclave?
            // Or could they be different enclaves running the same firmware?
            // What is the consequence if they are?
            println!("msg3 and collateral_quote came from different systems");
            return Err(ProxyAttestationServerError::MismatchError {
                variable: "function msg3 msg3_quote.report_body.mr_enclave.m",
                expected: collateral_quote.report_body.mr_enclave.m.to_vec(),
                received: msg3_quote.report_body.mr_enclave.m.to_vec(),
            });
        }

        // All's good. Generate a Certificate from the CSR...
        let cert = crate::attestation::convert_csr_to_certificate(&csr)?;

        let root_cert_der = crate::attestation::get_ca_certificate()?;

        let response_bytes = transport_protocol::serialize_cert_chain(&cert.to_der()?, &root_cert_der)?;
        
        let response_b64 = base64::encode(&response_bytes);

        return Ok(response_b64);
    }
}

fn generate_sgx_symmetric_keys(
    ecdh: &sgx_ec256_dh_shared_t,
) -> Result<(sgx_cmac_128bit_tag_t, sgx_cmac_128bit_tag_t), ProxyAttestationServerError> {
    let zero_key = [0; 16];
    let kdk = sgx_ucrypto::rsgx_rijndael128_cmac_msg(&zero_key, &ecdh.s)?;
    let smk_input: [u8; 7] = [0x01, 'S' as u8, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let smk = sgx_ucrypto::rsgx_rijndael128_cmac_msg(&kdk, &smk_input)?;

    let vk_input: [u8; 6] = [0x01, 'V' as u8, 'K' as u8, 0x00, 0x80, 0x00];
    let vk = sgx_ucrypto::rsgx_rijndael128_cmac_msg(&kdk, &vk_input)?;

    Ok((smk, vk))
}

fn proc_msg1(
    msg1: &sgx_ra_msg1_t,
    smk: &sgx_cmac_128bit_tag_t,
    private_key: &sgx_ec256_private_t,
    public_key: &sgx_ec256_public_t,
) -> Result<sgx_ra_msg2_t, ProxyAttestationServerError> {
    let gid_little_endian = &msg1.gid;
    let gid = reverse(&gid_little_endian.to_vec());

    let sig_rl = get_sigrl(&gid)?;
    if sig_rl != "" {
        //TODO
        return Err(ProxyAttestationServerError::MissingFieldError(
            "Signature Revocation List (unimplemented)",
        ));
    }
    let spid = [
        0x4E, 0xE1, 0x2C, 0xF0, 0x48, 0x00, 0x04, 0x0B, 0xAB, 0x6F, 0xFD, 0xD4, 0x5F, 0xDF, 0xD9,
        0xBF,
    ];

    let mut gb_ga_vec = Vec::new();
    gb_ga_vec.append(&mut public_key.gx.to_vec());
    gb_ga_vec.append(&mut public_key.gy.to_vec());
    gb_ga_vec.append(&mut msg1.g_a.gx.to_vec());
    gb_ga_vec.append(&mut msg1.g_a.gy.to_vec());

    let mut gb_ga = Crap {
        value: [0; 4 * sgx_types::SGX_ECP256_KEY_SIZE],
    };
    gb_ga.value.copy_from_slice(&gb_ga_vec[..]);

    let sgx_ecc_handle = sgx_ucrypto::SgxEccHandle::new();

    sgx_ecc_handle.open()?;

    let sgx_sig = sgx_ecc_handle.ecdsa_sign_msg(&gb_ga, private_key)?;
    //AES-CMAC of gb, spid 2-byte TYPE, 2-byte KDF-ID, and sign_gb_ga using
    //SMK as the AES-CMAC key.

    let mac: [u8; 16] = [0; 16];

    let mut msg2 = sgx_ra_msg2_t {
        g_b: *public_key,
        spid: sgx_spid_t { id: spid },
        quote_type: QUOTE_TYPE,
        kdf_id: 0x0001,      // AES_CMAC_KDF_ID
        sign_gb_ga: sgx_sig, // sgx_ec256_signature_t
        mac: mac,
        sig_rl_size: 0,
        sig_rl: [0; 0],
    };

    let mac = {
        let mut cmac_handle = std::ptr::null_mut();
        let init_ret = sgx_ucrypto::rsgx_cmac128_init(&smk, &mut cmac_handle);
        //TODO
        assert!(init_ret == sgx_status_t::SGX_SUCCESS);

        let update_ret = sgx_ucrypto::rsgx_cmac128_update_msg(&msg2.g_b, cmac_handle);
        //TODO
        assert!(update_ret == sgx_status_t::SGX_SUCCESS);

        let update_ret = sgx_ucrypto::rsgx_cmac128_update_msg(&msg2.spid, cmac_handle);
        //TODO
        assert!(update_ret == sgx_status_t::SGX_SUCCESS);

        let update_ret = sgx_ucrypto::rsgx_cmac128_update_msg(&msg2.quote_type, cmac_handle);
        //TODO
        assert!(update_ret == sgx_status_t::SGX_SUCCESS);

        let update_ret = sgx_ucrypto::rsgx_cmac128_update_msg(&msg2.kdf_id, cmac_handle);
        //TODO
        assert!(update_ret == sgx_status_t::SGX_SUCCESS);

        let update_ret = sgx_ucrypto::rsgx_cmac128_update_msg(&msg2.sign_gb_ga, cmac_handle);
        assert!(update_ret == sgx_status_t::SGX_SUCCESS);

        let mut hash = sgx_cmac_128bit_tag_t::default();
        let final_ret = sgx_ucrypto::rsgx_cmac128_final(cmac_handle, &mut hash);
        assert!(final_ret == sgx_status_t::SGX_SUCCESS);

        let close_ret = sgx_ucrypto::rsgx_cmac128_close(cmac_handle);
        assert!(close_ret == sgx_status_t::SGX_SUCCESS);

        hash
    };
    msg2.mac = mac;

    sgx_ecc_handle.close()?;
    Ok(msg2)
}

fn reverse(input: &Vec<u8>) -> Vec<u8> {
    let mut output = Vec::new();
    for i in (0..input.len()).rev() {
        output.push(input[i]);
    }
    output
}

fn get_sigrl(gid: &Vec<u8>) -> Result<String, ProxyAttestationServerError> {
    let mut gid_string = String::new();
    for i in 0..gid.len() {
        gid_string = format!("{:}{:02x}", gid_string, gid[i]);
    }
    let url = "https://api.trustedservices.intel.com:443/sgx/dev/attestation/v3/sigrl/";
    let url = url.to_string() + &gid_string;

    let mut curl_request = Easy::new();
    curl_request.url(&url)?;

    curl_request.ssl_verify_host(false)?;
    curl_request.ssl_verify_peer(false)?;

    let mut list = List::new();
    let token_header = "Ocp-Apim-Subscription-Key: ".to_string() + &TOKEN.to_string();
    list.append(&token_header)?;
    curl_request.http_headers(list)?;

    let mut transfer = curl_request.transfer();
    transfer.write_function(|buf| Ok(buf.len()))?;

    transfer.perform()?;

    Ok("".to_string())
}

#[derive(Copy, Clone)]
struct Crap {
    value: [u8; 4 * sgx_types::SGX_ECP256_KEY_SIZE],
}

unsafe impl ContiguousMemory for Crap {}

#[derive(Copy, Clone)]
struct SigT {
    pub value: [u8; 680],
}

unsafe impl ContiguousMemory for SigT {}

fn authenticate_msg3(
    msg1: &sgx_ra_msg1_t,
    msg2: &sgx_ra_msg2_t,
    msg3: &sgx_ra_msg3_t,
    msg3_quote: &sgx_quote_t,
    sig: &Vec<u8>,
    smk: &sgx_cmac_128bit_tag_t,
    vk: &sgx_cmac_128bit_tag_t,
    expected_enclave_hash: &Vec<u8>,
) -> Result<String, ProxyAttestationServerError> {
    // now we've got the msg3 and pubkey quote, verify msg3
    // compare g_a in msg3 with local g_a
    if msg3.g_a.gx != msg1.g_a.gx || (msg3.g_a.gy != msg1.g_a.gy) {
        //TODO
        assert!(false);
    }
    // verify the message MAC using SMK
    let mac = {
        let mut cmac_handle = std::ptr::null_mut();
        let init_ret = sgx_ucrypto::rsgx_cmac128_init(&smk, &mut cmac_handle);
        //TODO
        assert!(init_ret == sgx_status_t::SGX_SUCCESS);

        let update_ret = sgx_ucrypto::rsgx_cmac128_update_msg(&msg3.g_a, cmac_handle);
        //TODO
        assert!(update_ret == sgx_status_t::SGX_SUCCESS);

        let update_ret = sgx_ucrypto::rsgx_cmac128_update_msg(&msg3.ps_sec_prop, cmac_handle);
        //TODO
        assert!(update_ret == sgx_status_t::SGX_SUCCESS);

        let update_ret = sgx_ucrypto::rsgx_cmac128_update_msg(msg3_quote, cmac_handle);
        //TODO
        assert!(update_ret == sgx_status_t::SGX_SUCCESS);

        let mut sig_array: [u8; 680] = [0; 680];
        sig_array.copy_from_slice(&sig[..]);
        let sig_struct = SigT { value: sig_array };
        let update_ret = sgx_ucrypto::rsgx_cmac128_update_msg(&sig_struct, cmac_handle);
        //TODO
        assert!(update_ret == sgx_status_t::SGX_SUCCESS);

        let mut hash = sgx_cmac_128bit_tag_t::default();
        let final_ret = sgx_ucrypto::rsgx_cmac128_final(cmac_handle, &mut hash);
        //TODO
        assert!(final_ret == sgx_status_t::SGX_SUCCESS);

        let close_ret = sgx_ucrypto::rsgx_cmac128_close(cmac_handle);
        //TODO
        assert!(close_ret == sgx_status_t::SGX_SUCCESS);

        hash
    };

    if mac != msg3.mac {
        //TODO
        assert!(false);
    }

    // verify the hash value that is internal to the quote
    let sha_handle = SgxShaHandle::new();

    sha_handle.init()?;
    sha_handle.update_msg(&msg1.g_a)?;
    sha_handle.update_msg(&msg2.g_b)?;
    sha_handle.update_msg(vk)?;

    let expected_hash = sha_handle.get_hash()?;
    if expected_hash != msg3_quote.report_body.report_data.d[0..32] {
        println!("proxy_attestation_server::attestation::sgx::authenticate_msg3 msg3_quote hash don't match");
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "msg3_quote.report_body.report_data.d[0..32]",
            expected: expected_hash.to_vec(),
            received: msg3_quote.report_body.report_data.d[0..32].to_vec(),
        });
    }

    if msg3_quote.report_body.mr_enclave.m != expected_enclave_hash[0..32] {
        println!("proxy_attestation_server::attestation::sgx::authenticate_msg3 mr_enclave.m hash don't match");
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "function authenticate_msg3 msg3_quote.report_body.mr_enclave.m",
            expected: expected_enclave_hash[0..32].to_vec(),
            received: msg3_quote.report_body.mr_enclave.m.to_vec(),
        });
    }
    // Verify the msg3 quote with the attestation server
    let msg3_epid_pseudonym = ias_verify_attestation_evidence(&msg3_quote, &sig)?;

    Ok(msg3_epid_pseudonym)
}

fn ias_verify_attestation_evidence(
    quote: &sgx_types::sgx_quote_t,
    sig: &Vec<u8>,
) -> Result<String, ProxyAttestationServerError> {
    let mut json_string = "{\"isvEnclaveQuote\":\"".to_string();

    let mut quote_slice = unsafe { any_as_u8_slice(quote) }.to_vec();
    quote_slice.append(&mut sig.clone());

    json_string = json_string + &base64::encode(&quote_slice);
    json_string = json_string + &"\"}".to_string();

    let mut json_string_reader = stringreader::StringReader::new(&json_string);

    let url = "https://api.trustedservices.intel.com:443/sgx/dev/attestation/v3/report";

    let mut curl_request = Easy::new();
    curl_request.url(&url)?;

    let mut list = List::new();
    list.append("Content-Type: application/json")?;
    let token_header = "Ocp-Apim-Subscription-Key: ".to_string() + &TOKEN.to_string();
    list.append(&token_header)?;
    curl_request.http_headers(list)?;

    curl_request.post(true)?;
    curl_request.post_field_size(json_string.len() as u64)?;

    let mut received_body = std::string::String::new();
    let mut received_header = std::string::String::new();
    {
        let mut transfer = curl_request.transfer();
        transfer.read_function(|buf| Ok(json_string_reader.read(buf).unwrap_or(0)))?;
        transfer.write_function(|buf| {
            // TODO Should find return a curl::easy::handler::WriteError
            received_body.push_str(std::str::from_utf8(buf).unwrap());
            Ok(buf.len())
        })?;
        transfer.header_function(|buf| {
            // TODO Should find return a curl::easy::handler::WriteError
            received_header.push_str(std::str::from_utf8(buf).unwrap());
            true
        })?;

        transfer.perform()?;
    }

    let header_lines: Vec<&str> = {
        let lines = received_header.split("\n");
        lines.collect()
    };
    let mut header_fields = std::collections::HashMap::new();
    for this_line in header_lines.iter() {
        let fields: Vec<&str> = this_line.split(":").collect();
        if fields.len() == 2 {
            header_fields.insert(fields[0], fields[1]);
        }
    }

    let signature = header_fields["X-IASReport-Signature"].trim();
    let decoded_signature = base64::decode(&signature)?;

    // Verify the signature on the body
    {
        // First, parse the certificates
        let certs = header_fields["X-IASReport-Signing-Certificate"];
        let certs = percent_encoding::percent_decode(certs.as_bytes()).decode_utf8()?;

        let cert1_index =
            certs
                .rfind("-----BEGIN CERTIFICATE-----")
                .ok_or(ProxyAttestationServerError::MissingFieldError(
                    "-----BEGIN CERTIFICATE-----",
                ))?;
        let cert1 = certs[1..cert1_index].to_string();
        //let cert2 = certs[cert1_index..].to_string();
        let x509 = openssl::x509::X509::from_pem(cert1.as_bytes())?;
        let public_key = x509.public_key()?;

        let mut verifier =
            openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public_key)?;
        verifier.update(received_body.as_bytes())?;
        let result = verifier.verify(&decoded_signature)?;
        if !result {
            return Err(ProxyAttestationServerError::FailedToVerifyError("decoded_signature"));
        }
        // TODO: Authenticate the certificate chain. Right now, all we are doing is authenticating
        // the received signature with a key provided in a certificate. We are not authenticating that
        // certificate or any certificate in it's chain. This is not really necessary for Veracruz,
        // but is important for SGX if we were to productize
    }

    let v: serde_json::Value = serde_json::from_str(&received_body)?;

    Ok(v["epidPseudonym"]
        .as_str()
        //TODO
        .ok_or(ProxyAttestationServerError::MissingFieldError("epidPseudonym"))?
        .to_string())
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

fn authenticate_pubkey_quote(
    pubkey_challenge: &[u8; 16],
    pubkey_quote: &sgx_quote_t,
    pubkey_sig: &Vec<u8>,
) -> Result<(String, Vec<u8>), ProxyAttestationServerError> {
    // verify the challge value value that is internal to the pubkey quote
    if *pubkey_challenge != pubkey_quote.report_body.report_data.d[0..16] {
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "pubkey_challenge",
            expected: pubkey_challenge.to_vec(),
            received: pubkey_quote.report_body.report_data.d[0..16].to_vec(),
        });
    }
    // extract the pubkey hash value that is internal to the pubkey quote
    let pubkey_hash = &pubkey_quote.report_body.report_data.d[16..48];

    // verify the pubkey quote with the attestation server
    let pubkey_epid_pseudonym = ias_verify_attestation_evidence(&pubkey_quote, &pubkey_sig)?;
    Ok((
        pubkey_epid_pseudonym,
        pubkey_hash.to_vec(),
    ))
}
