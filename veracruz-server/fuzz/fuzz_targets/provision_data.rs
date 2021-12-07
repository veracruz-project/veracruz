//! Fuzz provisioning data
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root director for licensing
//! and copyright information.

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::fs::File;
use std::io::prelude::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use transport_protocol;

use policy_utils::policy::Policy;

const ENCLAVE_STATE_DATA_SOURCES_LOADING: u8 = 1;

fuzz_target!(|buffer: &[u8]| {
    // Fuzz a  valid protocol
    if let Ok(request) = transport_protocol::serialize_program(buffer) {
        println!("program: {:?}", request);

        let mut f = File::open("../test-collateral/one_data_source_policy.json").unwrap();
        let mut policy = String::new();
        f.read_to_string(&mut policy).unwrap();

        let policy = Policy::new(&policy).unwrap();

        let (veracruz_server, session_id) = init_veracruz_server_and_tls_session(policy).unwrap();
        let enclave_cert = enclave_self_signed_cert(&veracruz_server).unwrap();

        let client_cert_filename = "../test-collateral/client_rsa_cert.pem";
        let client_key_filename = "../test-collateral/client_rsa_key.pem";
        let cert_hash = ring::digest::digest(&ring::digest::SHA256, enclave_cert.as_ref());

        let mut client_session = create_client_test_session(
            &veracruz_server,
            client_cert_filename,
            client_key_filename,
            cert_hash.as_ref().to_vec(),
        );

        let (server_tls_tx, client_tls_rx): (
            std::sync::mpsc::Sender<std::vec::Vec<u8>>,
            std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        ) = std::sync::mpsc::channel();
        let (client_tls_tx, server_tls_rx): (
            std::sync::mpsc::Sender<std::vec::Vec<u8>>,
            std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        ) = std::sync::mpsc::channel();

        let flag_main = Arc::new(AtomicBool::new(true));
        let flag_server = flag_main.clone();

        let server_loop_handle = std::thread::spawn(move || {
            server_tls_loop(
                flag_server,
                &veracruz_server,
                session_id,
                server_tls_tx,
                server_tls_rx,
            );
        });

        let rst = client_tls_send(
            &client_tls_tx,
            &client_tls_rx,
            &mut client_session,
            &request,
        )
        .unwrap();
        let rst = protobuf::parse_from_bytes::<transport_protocol::RuntimeManagerResponse>(&rst);
        assert!(rst.is_ok());

        flag_main.store(false, Ordering::SeqCst);

        server_loop_handle.join().unwrap();
    }
});

use veracruz_server::veracruz_server::VeracruzServer;

fn init_veracruz_server_and_tls_session(
    policy: Policy,
) -> Result<(VeracruzServerEnclave, u32), String> {
    VeracruzServerEnclave::new(&policy).and_then(|veracruz_server| {
        veracruz_server.new_tls_session().and_then(|session_id| {
            if session_id != 0 {
                Ok((veracruz_server, session_id))
            } else {
                Err("Session id is zero".to_string())
            }
        })
    })
}

fn enclave_self_signed_cert(
    veracruz_server: &VeracruzServerEnclave,
) -> Result<rustls::Certificate, String> {
    let enclave_cert_vec = veracruz_server.get_enclave_cert()?;
    Ok(rustls::Certificate(enclave_cert_vec))
}

fn read_cert_file(filename: &str) -> rustls::Certificate {
    let mut cert_file = std::fs::File::open(filename).expect(&format!(
        "Error opening certificate file {} for reading",
        filename
    ));
    let mut cert_buffer = std::vec::Vec::new();
    cert_file.read_to_end(&mut cert_buffer).expect(&format!(
        "Error reading certificate file {} to end",
        filename
    ));
    let mut cursor = std::io::Cursor::new(cert_buffer);
    let certs = rustls::internal::pemfile::certs(&mut cursor)
        .expect(&format!("Error reading certificates from {}", filename));
    assert!(certs.len() > 0);
    certs[0].clone()
}

fn read_priv_key_file(filename: &str) -> rustls::PrivateKey {
    let mut key_file = std::fs::File::open(filename)
        .expect(&format!("Error opening key file {} for reading", filename));
    let mut key_buffer = std::vec::Vec::new();
    key_file.read_to_end(&mut key_buffer).expect(&format!(
        "Error reading private key file {} to end",
        filename
    ));
    let mut cursor = std::io::Cursor::new(key_buffer);
    let rsa_keys = rustls::internal::pemfile::rsa_private_keys(&mut cursor)
        .expect("file contains invalid rsa private key");
    rsa_keys[0].clone()
}

fn create_client_test_session(
    veracruz_server: &dyn veracruz_server::VeracruzServer,
    client_cert_filename: &str,
    client_key_filename: &str,
    cert_hash: Vec<u8>,
) -> rustls::ClientSession {
    let client_cert = read_cert_file(client_cert_filename);

    let client_priv_key = read_priv_key_file(client_key_filename);

    let mut client_config = rustls::ClientConfig::new_self_signed();
    let mut client_cert_vec = std::vec::Vec::new();
    client_cert_vec.push(client_cert);
    client_config.set_single_client_cert(client_cert_vec, client_priv_key);
    client_config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    client_config.pinned_cert_hashes.push(cert_hash);

    let enclave_name = veracruz_server
        .get_enclave_name()
        .expect("Error obtaining Enclave name");
    let dns_name_ret = webpki::DNSNameRef::try_from_ascii_str(enclave_name.as_str());
    assert!(dns_name_ret.is_ok());
    let dns_name = dns_name_ret.expect(&format!(
        "Error obtaining DNS name reference from enclave {}",
        enclave_name
    ));
    rustls::ClientSession::new(&std::sync::Arc::new(client_config), dns_name)
}

fn client_tls_send(
    tx: &std::sync::mpsc::Sender<std::vec::Vec<u8>>,
    rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
    session: &mut dyn rustls::Session,
    send_data: &[u8],
) -> Result<Vec<u8>, String> {
    session
        .write_all(&send_data)
        .map_err(|_| format!("Error writing session data: {:?}", send_data))?;

    let mut output: std::vec::Vec<u8> = std::vec::Vec::new();

    session
        .write_tls(&mut output)
        .map_err(|_| format!("Error writing TLS data: {:?}", output))?;

    let cloned = &output.clone();

    tx.send(output)
        .map_err(|_| format!("Error sending output: {:?}", cloned))?;

    loop {
        let received = rx.try_recv();
        let cloned = &received.clone();

        if received.is_ok() && (!session.is_handshaking() || session.wants_read()) {
            let received =
                received.map_err(|_| format!("Error interpreting received data: {:?}", cloned))?;

            let mut slice = &received[..];
            session
                .read_tls(&mut slice)
                .map_err(|_| format!("Error reading TLS data: {:?}", slice))?;
            session
                .process_new_packets()
                .map_err(|_| "Error processing new packets".to_string())?;

            let mut received_buffer: std::vec::Vec<u8> = std::vec::Vec::new();

            match session.read_to_end(&mut received_buffer) {
                Err(reason) => {
                    return Err(format!(
                        "client_tls_send: session.read_to_end failed with {}",
                        reason
                    ))
                }
                Ok(num_bytes) => {
                    if num_bytes > 0 {
                        return Ok(received_buffer);
                    }
                }
            }
        } else if session.wants_write() {
            let mut output: std::vec::Vec<u8> = std::vec::Vec::new();
            session
                .write_tls(&mut output)
                .map_err(|_| format!("Error writing TLS data: {:?}", output))?;
            let res = tx.send(output);

            match res {
                Ok(_) => (),
                Err(err) => return Err(format!("Error in tx.send() {:?}", err)),
            };
        } else {
        }
    }
}

fn server_tls_loop(
    flag: Arc<AtomicBool>,
    veracruz_server: &dyn veracruz_server::VeracruzServer,
    session_id: u32,
    tx: std::sync::mpsc::Sender<std::vec::Vec<u8>>,
    rx: std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
) {
    while flag.load(Ordering::SeqCst) {
        let received = rx.try_recv();
        let received_buffer = received.unwrap_or_else(|_| std::vec::Vec::new());

        if received_buffer.len() > 0 {
            let output_data_option_result = veracruz_server.tls_data(session_id, received_buffer);
            match output_data_option_result {
                Err(err) => panic!(format!("tls_data failed with error: {:?}", err)),
                Ok(output_data_option) => match output_data_option {
                    Some(output_data) => {
                        for output in &output_data {
                            if output.len() > 0 {
                                tx.send(output.clone())
                                    .expect(&format!("Failed to send output: {:?}", output));
                            }
                        }
                    }
                    None => (),
                },
            }
        }
    }
}

fn check_enclave_state(
    client_session: &mut dyn rustls::Session,
    client_tls_tx: &std::sync::mpsc::Sender<std::vec::Vec<u8>>,
    client_tls_rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
    expecting: u8,
) {
    match request_enclave_state(client_session, client_tls_tx, client_tls_rx) {
        Err(error_msg) => panic!(
            "Requesting enclave state failed with message: {}",
            error_msg
        ),
        Ok(encoded_state) => {
            let parsed = transport_protocol::parse_response(&encoded_state);

            if parsed.has_state() {
                let state = parsed.get_state().get_state().to_vec();

                if state == vec![expecting] {
                    println!("Enclave state as expected.")
                } else {
                    panic!(
                        "Enclave state mismatch.  Expecting {:?} but found {:?}!",
                        expecting, state
                    );
                }
            } else {
                panic!("Response did not contain an enclave state as expected.");
            }
        }
    }
}

fn request_enclave_state(
    client_session: &mut dyn rustls::Session,
    client_tls_tx: &std::sync::mpsc::Sender<std::vec::Vec<u8>>,
    client_tls_rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let serialized_enclave_state_request = transport_protocol::serialize_request_enclave_state()?;

    client_tls_send(
        client_tls_tx,
        client_tls_rx,
        client_session,
        &serialized_enclave_state_request[..],
    )
}
