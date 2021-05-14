//! Tests specified to the Veracruz proxy attestation service
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

extern crate psa_attestation;
extern crate sgx_urts;

use psa_attestation::{
    psa_initial_attest_get_token, psa_initial_attest_load_key, t_cose_sign1_get_verification_pubkey,
};

use curl::easy::{Easy, List};

use rand::Rng;
use std::convert::TryInto;
use std::io::Read;
use std::mem;
use std::sync::Once;

use sgx_types::{
    sgx_attributes_t, sgx_calc_quote_size, sgx_ec256_public_t, sgx_get_quote, sgx_init_quote,
    sgx_launch_token_t, sgx_misc_attribute_t, sgx_quote_nonce_t, sgx_quote_sign_type_t,
    sgx_quote_t, sgx_ra_context_t, sgx_ra_get_msg1, sgx_ra_msg1_t, sgx_ra_msg2_t, sgx_ra_msg3_t,
    sgx_ra_proc_msg2, sgx_report_t, sgx_spid_t, sgx_status_t, sgx_target_info_t, uint8_t,
};
use sgx_urts::SgxEnclave;

extern crate sgx_root_enclave_bind;

use sgx_root_enclave_bind::{
    _quote_nonce, _ra_msg2_t, _ra_msg3_t, _report_t, _sgx_ec256_public_t, _target_info_t,
    sgx_root_enclave_get_firmware_version, sgx_root_enclave_get_firmware_version_len,
    sgx_root_enclave_init_remote_attestation_enc, sgx_root_enclave_sgx_get_pubkey_report, sgx_root_enclave_sgx_ra_get_ga,
    sgx_root_enclave_sgx_ra_get_msg3_trusted, sgx_root_enclave_sgx_ra_proc_msg2_trusted,
};

static ENCLAVE_FILE: &'static str = "/work/veracruz/trustzone-root-enclave/bin/sgx_root_enclave.signed.so";

#[test]
fn test_sgx_attestation() {
    let url_base = "127.0.0.1:3016";

    // start the server (if it's not already started)
    setup();

    // create the enclave
    let debug = 1;
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    let enclave = SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
    .unwrap();

    let (protocol, firmware_version) = {
        let mut gfvl_ret: u32 = 0;
        let mut fv_length: u64 = 0;
        let gfvl_result = unsafe {
            sgx_root_enclave_get_firmware_version_len(enclave.geteid(), &mut gfvl_ret, &mut fv_length)
        };
        assert!(gfvl_result == 0);
        assert!(gfvl_ret == 0);

        let mut output = Vec::with_capacity(fv_length as usize);
        let p_output = output.as_mut_ptr();

        let mut gfv_ret = sgx_status_t::SGX_SUCCESS as u32;
        let gfv_result = unsafe {
            sgx_root_enclave_get_firmware_version(enclave.geteid(), &mut gfv_ret, p_output, fv_length)
        };
        assert!(gfv_result == sgx_status_t::SGX_SUCCESS as u32);
        assert!(gfv_ret == sgx_status_t::SGX_SUCCESS as u32);

        unsafe { output.set_len(fv_length as usize) };
        ("sgx", std::str::from_utf8(&output[..]).unwrap().to_string())
    };

    let (public_key, device_id) = send_sgx_start(&url_base, protocol, &firmware_version);

    let mut attestation_context: sgx_ra_context_t = 0;
    let mut ira_ret: u32 = 0;
    let ira_result = unsafe {
        sgx_root_enclave_init_remote_attestation_enc(
            enclave.geteid(),
            &mut ira_ret,
            public_key.as_ptr() as *const u8,
            public_key.len().try_into().unwrap(),
            &mut attestation_context,
        )
    };
    assert!(ira_result == 0);
    assert!(ira_ret == sgx_status_t::SGX_SUCCESS as u32);

    let mut msg1 = sgx_ra_msg1_t::default();
    let bindgen_sgx_root_enclave_sgx_ra_get_ga = unsafe {
        mem::transmute::<
            unsafe extern "C" fn(u64, *mut u32, u32, *mut _sgx_ec256_public_t) -> u32,
            unsafe extern "C" fn(
                u64,
                *mut sgx_status_t,
                u32,
                *mut sgx_ec256_public_t,
            ) -> sgx_status_t,
        >(sgx_root_enclave_sgx_ra_get_ga)
    };
    let msg1_ret = unsafe {
        sgx_ra_get_msg1(
            attestation_context,
            enclave.geteid(),
            bindgen_sgx_root_enclave_sgx_ra_get_ga,
            &mut msg1,
        )
    };
    assert!(msg1_ret == sgx_status_t::SGX_SUCCESS);

    let (challenge, msg2) = send_sgx_msg1(&url_base, &attestation_context, &msg1, device_id);

    let (msg3, msg3_quote, msg3_sig, pubkey_quote, pubkey_quote_sig) =
        attestation_challenge(&enclave, &challenge, &attestation_context, &msg2)
            .expect("Attestation challenge failed");
    send_msg3(
        url_base,
        &attestation_context,
        &msg3,
        &msg3_quote,
        &msg3_sig,
        &pubkey_quote,
        &pubkey_quote_sig,
        device_id,
    );
    enclave.destroy();
}

#[test]
fn test_psa_attestation() {
    // start the server (if it's not already started)
    setup();

    let fake_device_id: i32 = 55378008;
    let fake_enclave_name = "snork";

    let private_key = {
        let rng = ring::rand::SystemRandom::new();
        // ECDSA prime256r1 generation.
        let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("Error generating PKCS-8");
        pkcs8_bytes.as_ref()[38..70].to_vec()
    };

    let mut key_handle: u16 = 0;
    let status = unsafe {
        psa_initial_attest_load_key(
            private_key.as_ptr(),
            private_key.len() as u64,
            &mut key_handle,
        )
    };
    assert!(status == 0);

    let mut public_key = std::vec::Vec::with_capacity(128); // TODO: Don't do this
    let mut public_key_size: u64 = 0;
    let ret = unsafe {
        t_cose_sign1_get_verification_pubkey(
            key_handle,
            public_key.as_mut_ptr() as *mut u8,
            public_key.capacity() as u64,
            &mut public_key_size as *mut u64,
        )
    };
    assert!(ret == 0);
    unsafe { public_key.set_len(public_key_size as usize) };

    let pubkey_hash = ring::digest::digest(&ring::digest::SHA256, public_key.as_ref());
    // create a fake device with a public key, fake URL
    let connection = crate::orm::establish_connection();
    crate::orm::update_or_create_device(
        &connection,
        fake_device_id,
        &pubkey_hash.as_ref().to_vec(),
        fake_enclave_name.to_string(),
    )
    .unwrap();

    let fake_challenge = rand::thread_rng().gen::<[u8; 32]>();
    let fake_veracruz_hash = rand::thread_rng().gen::<[u8; 32]>();
    let fake_enclave_cert_hash = rand::thread_rng().gen::<[u8; 32]>();
    let fake_enclave_name = "foobar";
    let mut token = Vec::with_capacity(16 * 1024); // TODO: Don't do this
    let mut token_size: u64 = 0;
    // generate the PSA attestation token
    let status = unsafe {
        psa_initial_attest_get_token(
            fake_veracruz_hash.as_ptr() as *const u8,
            fake_veracruz_hash.len() as u64,
            fake_enclave_cert_hash.as_ptr() as *const u8,
            fake_enclave_cert_hash.len() as u64,
            fake_enclave_name.as_ptr() as *const i8,
            fake_enclave_name.len() as u64,
            fake_challenge.as_ptr() as *const u8,
            fake_challenge.len() as u64,
            token.as_mut_ptr() as *mut u8,
            token.capacity() as u64,
            &mut token_size as *mut u64,
        )
    };
    assert!(status == 0);
    unsafe { token.set_len(token_size.try_into().unwrap()) }

    let serialized_pat =
        transport_protocol::serialize_psa_attestation_token(&token, public_key.as_ref(), fake_device_id);
    let encoded_token = base64::encode(&serialized_pat);

    let url = "127.0.0.1:3016/VerifyPAT";
    let received_buffer =
        post_buffer(&url, &encoded_token).expect("Failed to send buffer to proxy attestation server");
}

static SETUP: Once = Once::new();
pub fn setup() {
    SETUP.call_once(|| {
        let _main_loop_handle = std::thread::spawn(move || super::main());
    });
}

fn send_sgx_start(url_base: &str, protocol: &str, firmware_version: &str) -> (Vec<u8>, i32) {
    let serialized_start_msg = transport_protocol::serialize_start_msg(protocol, firmware_version);
    let encoded_start_msg = base64::encode(&serialized_start_msg);
    println!(
        "proxy-attestation-server::test::send_sgx_start encoded_start_msg:{:?}",
        encoded_start_msg
    );

    let url = format!("{:}/Start", url_base);

    let received_body = post_buffer(&url, &encoded_start_msg).unwrap();

    let body_vec =
        base64::decode(&received_body).expect("Failed to base64 decode the received body");
    let parsed = transport_protocol::parse_request(&body_vec);
    assert!(parsed.has_attestation_init());
    let attestation_init = parsed.get_attestation_init();
    let (public_key, device_id) = transport_protocol::parse_attestation_init(attestation_init);
    (public_key, device_id)
}

fn send_sgx_msg1(
    url_base: &str,
    attestation_context: &sgx_ra_context_t,
    msg1: &sgx_ra_msg1_t,
    device_id: i32,
) -> (Vec<u8>, sgx_ra_msg2_t) {
    let serialized_msg1 = transport_protocol::serialize_msg1(*attestation_context, msg1, device_id);
    let encoded_msg1 = base64::encode(&serialized_msg1);
    let mut encoded_msg1_reader = stringreader::StringReader::new(&encoded_msg1);

    let url = format!("{:}/SGX/Msg1", url_base);

    let received_body = post_buffer(&url, &encoded_msg1).unwrap();

    let body_vec =
        base64::decode(&received_body).expect("Failed to base64 decode the received body");
    let parsed = transport_protocol::parse_request(&body_vec);
    assert!(parsed.has_attestation_challenge());
    let (_context, msg2, challenge) = transport_protocol::parse_attestation_challenge(&parsed);
    (challenge.to_vec(), msg2)
}

fn send_msg3(
    url_base: &str,
    attestation_context: &sgx_ra_context_t,
    msg3: &sgx_ra_msg3_t,
    msg3_quote: &sgx_quote_t,
    msg3_sig: &Vec<u8>,
    pubkey_quote: &sgx_quote_t,
    pubkey_quote_sig: &Vec<u8>,
    device_id: i32,
) {
    let serialized_tokens = transport_protocol::serialize_attestation_tokens(
        *attestation_context,
        msg3,
        msg3_quote,
        msg3_sig,
        pubkey_quote,
        pubkey_quote_sig,
        device_id,
    );
    let encoded_tokens = base64::encode(&serialized_tokens);

    let url = format!("{:}/SGX/Msg3", url_base);

    let received_buffer = post_buffer(&url, &encoded_tokens).unwrap();

    assert!(received_buffer == "All's well that ends well");
}

fn attestation_challenge(
    enclave: &SgxEnclave,
    pubkey_challenge: &Vec<u8>,
    context: &sgx_ra_context_t,
    msg2: &sgx_ra_msg2_t,
) -> Result<(sgx_ra_msg3_t, sgx_quote_t, Vec<u8>, sgx_quote_t, Vec<u8>), String> {
    let mut p_msg3 = std::ptr::null_mut();
    let mut msg3_size = 0;
    let msg2_size: u32 = std::mem::size_of::<sgx_ra_msg2_t>() as u32;
    let bindgen_sgx_root_enclave_sgx_ra_proc_msg2_trusted = unsafe {
        mem::transmute::<
            unsafe extern "C" fn(
                u64,
                *mut u32,
                u32,
                *const _ra_msg2_t,
                *const _target_info_t,
                *mut _report_t,
                *mut _quote_nonce,
            ) -> u32,
            unsafe extern "C" fn(
                u64,
                *mut sgx_status_t,
                u32,
                *const sgx_ra_msg2_t,
                *const sgx_target_info_t,
                *mut sgx_report_t,
                *mut sgx_quote_nonce_t,
            ) -> sgx_status_t,
        >(sgx_root_enclave_sgx_ra_proc_msg2_trusted)
    };
    let bindgen_sgx_root_enclave_sgx_ra_get_msg3_trusted = unsafe {
        mem::transmute::<
            unsafe extern "C" fn(
                u64,
                *mut u32,
                u32,
                u32,
                *mut _report_t,
                *mut _ra_msg3_t,
                u32,
            ) -> u32,
            unsafe extern "C" fn(
                u64,
                *mut sgx_status_t,
                u32,
                u32,
                *mut sgx_report_t,
                *mut sgx_ra_msg3_t,
                u32,
            ) -> sgx_status_t,
        >(sgx_root_enclave_sgx_ra_get_msg3_trusted)
    };
    let proc_msg2_ret = unsafe {
        sgx_ra_proc_msg2(
            *context,
            enclave.geteid(),
            bindgen_sgx_root_enclave_sgx_ra_proc_msg2_trusted,
            bindgen_sgx_root_enclave_sgx_ra_get_msg3_trusted,
            msg2,
            msg2_size,
            &mut p_msg3,
            &mut msg3_size,
        )
    };

    let p_msg3_byte = p_msg3 as *mut u8;
    if proc_msg2_ret != sgx_types::sgx_status_t::SGX_SUCCESS {
        println!("proc_msg2_ret:{:?}", proc_msg2_ret);
        Err("sgx_ra_proc_msg2 failed".to_string())
    } else {
        let msg3 = unsafe { *p_msg3 as sgx_ra_msg3_t };
        let quote_offset = std::mem::size_of::<sgx_ra_msg3_t>();
        let p_quote = unsafe { p_msg3_byte.offset(quote_offset as isize) as *mut sgx_quote_t };
        let quote = unsafe { *p_quote };

        let sig_offset = std::mem::size_of::<sgx_quote_t>();
        let sig_size = msg3_size as usize - quote_offset - sig_offset;

        let p_sig = unsafe { p_quote.offset(1) as *mut u8 };

        let sig = unsafe { std::slice::from_raw_parts_mut(p_sig, sig_size) };

        // initialize the quote (not sure what this does or what to do with the output)
        let mut target_info = sgx_target_info_t::default();
        let mut gid = sgx_types::sgx_epid_group_id_t::default();
        let siq_ret = unsafe { sgx_init_quote(&mut target_info, &mut gid) };
        assert!(siq_ret == sgx_types::sgx_status_t::SGX_SUCCESS);

        // get the public key report
        let mut pubkey_report = sgx_types::sgx_report_t::default();
        let bindgen_pubkey_report_ref = unsafe {
            mem::transmute::<&mut sgx_types::sgx_report_t, &mut _report_t>(&mut pubkey_report)
        };
        let bindgen_target_info_ref = unsafe {
            mem::transmute::<&mut sgx_types::sgx_target_info_t, &mut _target_info_t>(
                &mut target_info,
            )
        };
        let mut gpr_ret: u32 = sgx_types::sgx_status_t::SGX_SUCCESS as u32;
        let gpr_result = unsafe {
            sgx_root_enclave_sgx_get_pubkey_report(
                enclave.geteid(),
                &mut gpr_ret,
                pubkey_challenge.as_ptr(),
                pubkey_challenge.len().try_into().unwrap(),
                bindgen_target_info_ref,
                bindgen_pubkey_report_ref,
            )
        };
        assert!(gpr_result == sgx_status_t::SGX_SUCCESS as u32);
        assert!(gpr_ret == sgx_status_t::SGX_SUCCESS as u32);

        let mut pubkey_quote_size: u32 = 0;
        let cqs_ret = unsafe {
            sgx_calc_quote_size(std::ptr::null() as *const u8, 0, &mut pubkey_quote_size)
        };
        assert!(cqs_ret == sgx_status_t::SGX_SUCCESS);
        //pubkey_quote_size = 10000;
        println!("pubkey_quote_size:{:}", pubkey_quote_size);

        // TODO: add this to the policy
        let spid = sgx_spid_t {
            id: [
                0x4E, 0xE1, 0x2C, 0xF0, 0x48, 0x00, 0x04, 0x0B, 0xAB, 0x6F, 0xFD, 0xD4, 0x5F, 0xDF,
                0xD9, 0xBF,
            ],
        };

        let mut pubkey_quote_vec = Vec::with_capacity(pubkey_quote_size as usize);
        let p_qe_report: *mut sgx_report_t = std::ptr::null_mut();

        let p_sig_rl: *const uint8_t = std::ptr::null();
        let p_nonce_nul: *const sgx_quote_nonce_t = std::ptr::null();
        let gpq_result = unsafe {
            sgx_get_quote(
                &pubkey_report,
                sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE,
                &spid,
                p_nonce_nul,
                p_sig_rl,
                0,
                p_qe_report,
                pubkey_quote_vec.as_mut_ptr() as *mut sgx_quote_t,
                pubkey_quote_size,
            )
        };
        unsafe { pubkey_quote_vec.set_len(pubkey_quote_size as usize) }
        assert!(gpq_result == sgx_status_t::SGX_SUCCESS);

        let pubkey_quote = unsafe { *(pubkey_quote_vec.as_ptr() as *const sgx_quote_t) };

        let pubkey_quote_sig = pubkey_quote_vec[std::mem::size_of::<sgx_quote_t>()..].to_vec();

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
}
fn post_buffer(url: &str, data: &str) -> Result<String, String> {
    let mut data_reader = stringreader::StringReader::new(&data);
    let mut curl_request = Easy::new();
    curl_request
        .url(url)
        .expect(&format!("Error completing CURL request to {}", url));

    let mut headers = List::new();
    headers
        .append("Content-Type: application/octet-stream")
        .expect("Cannot append into CURL header list");

    curl_request
        .http_headers(headers)
        .expect("Cannot append into CURL header list");

    curl_request
        .post(true)
        .expect("Error setting POST for a curl request");
    curl_request
        .post_field_size(data.len() as u64)
        .expect(&format!("Error setting POST field size of {}", 0));
    curl_request
        .fail_on_error(true)
        .expect(&format!("Failed to set 'fail_on_error'"));

    let mut received_body = std::string::String::new();
    let mut received_header = std::string::String::new();
    {
        let mut transfer = curl_request.transfer();

        transfer
            .read_function(|buf| Ok(data_reader.read(buf).unwrap_or(0)))
            .expect("Error completing CURL transfer");

        transfer
            .write_function(|buf| {
                received_body.push_str(
                    std::str::from_utf8(buf)
                        .expect(&format!("Error converting data {:?} from UTF-8", buf)),
                );
                Ok(buf.len())
            })
            .expect("Error completing CURL transfer");
        transfer
            .header_function(|buf| {
                received_header.push_str(
                    std::str::from_utf8(buf)
                        .expect(&format!("Error converting data {:?} from UTF-8", buf)),
                );
                true
            })
            .expect("Error completing CURL transfer");

        transfer
            .perform()
            .expect(format!("Error performing CURL transfer to url:{:}", url).as_str());
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
    Ok(received_body)
}
