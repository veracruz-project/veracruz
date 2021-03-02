//! Durango-specific tests
//!
//! Note the tests need to be run in single-threaded mode.  Use
//!
//! ```
//! ... -- --test-threads 1
//! ```
//!
//! when invoking these tests with Cargo.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

const POLICY_FILENAME: &'static str = "../test-collateral/one_data_source_policy.json";
const TRIPLE_POLICY_FILENAME: &'static str = "../test-collateral/triple_policy.json";
const CLIENT_CERT_FILENAME: &'static str = "../test-collateral/client_rsa_cert.pem";
const CLIENT_KEY_FILENAME: &'static str = "../test-collateral/client_rsa_key.pem";

const PROGRAM_CLIENT_CERT_FILENAME: &'static str = "../test-collateral/program_client_cert.pem";
const PROGRAM_CLIENT_KEY_FILENAME: &'static str = "../test-collateral/program_client_key.pem";

const DATA_CLIENT_CERT_FILENAME: &'static str = "../test-collateral/data_client_cert.pem";
const DATA_CLIENT_KEY_FILENAME: &'static str = "../test-collateral/data_client_key.pem";

const RESULT_CLIENT_CERT_FILENAME: &'static str = "../test-collateral/result_client_cert.pem";

const MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME: &'static str =
    "../test-collateral/server_rsa_cert.pem";
const MOCK_ATTESTATION_ENCLAVE_NAME: &'static str = "localhost";

use crate::attestation::*;
use crate::veracruz_client::*;
use crate::error::*;
use std::{fs::File, io::prelude::*, io::Read, path::Path};

use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::{post, App, HttpRequest, HttpResponse, HttpServer};
use futures;
use veracruz_utils::EnclavePlatform;

#[test]
fn test_internal_read_all_bytes_in_file_succ() {
    let filename = "test.temp";
    let content = b"Hello, world!";
    if let Err(_) = File::create(filename).and_then(|mut file| file.write_all(content)) {
        panic!(format!("cannot create test file: {}", filename));
    }
    let rst = VeracruzClient::pub_read_all_bytes_in_file(filename);
    assert!(rst.is_ok());
    let rst_content = rst.unwrap();
    assert_eq!(rst_content, content);
}

#[test]
fn test_internal_read_all_bytes_in_file_invalid_file() {
    assert!(VeracruzClient::pub_read_all_bytes_in_file("../test-collateral/invalid_file").is_err());
}

#[test]
fn test_internal_read_all_bytes_in_file_invalid_path() {
    assert!(VeracruzClient::pub_read_all_bytes_in_file("invalid_path").is_err());
}

#[test]
fn test_internal_read_cert_succ() {
    assert!(VeracruzClient::pub_read_cert(CLIENT_CERT_FILENAME).is_ok());
}

#[test]
fn test_internal_read_cert_invalid_certificate() {
    assert!(VeracruzClient::pub_read_cert(CLIENT_KEY_FILENAME).is_err());
}

#[test]
fn test_internal_read_private_key_succ() {
    assert!(VeracruzClient::pub_read_private_key(CLIENT_KEY_FILENAME).is_ok());
}

#[test]
fn test_internal_read_cert_invalid_private_key() {
    assert!(VeracruzClient::pub_read_private_key(CLIENT_CERT_FILENAME).is_err());
}

#[test]
fn test_set_up_mock_object_for_attestation_handler() {
    // set up the attestation result as a mock object
    let handler = crate::attestation::MockAttestation::attestation_context();
    handler.expect().returning(|_, _| {
        Ok((
            VeracruzClient::pub_read_cert(MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME)
                .unwrap()
                .0,
            MOCK_ATTESTATION_ENCLAVE_NAME.to_string(),
        ))
    });
    let policy_json = std::fs::read_to_string(POLICY_FILENAME).unwrap();
    let policy: veracruz_utils::VeracruzPolicy =
        serde_json::from_str(policy_json.as_str()).unwrap();

    assert!(crate::attestation::MockAttestation::attestation(&policy, &EnclavePlatform::Mock).is_ok());
}

fn load_client_cert_and_private_key(
    cert_file: &str,
    pkey_file: &str,
    policy_file: &str,
) -> Result<
    (
        rustls::Certificate,
        rustls::PrivateKey,
        veracruz_utils::VeracruzPolicy,
    ),
    VeracruzClientError,
> {
    VeracruzClient::pub_read_cert(cert_file).and_then(|cert| {
        VeracruzClient::pub_read_private_key(pkey_file).and_then(|pkey| {
            let policy_json = std::fs::read_to_string(policy_file)?;
            let policy: veracruz_utils::VeracruzPolicy =
                serde_json::from_str(policy_json.as_str())?;
            Ok((cert, pkey, policy))
        })
    })
}

#[test]
fn test_internal_init_self_signed_cert_client_config_succ() {
    // set up the attestation result as a mock object
    let handler = crate::attestation::MockAttestation::attestation_context();
    handler.expect().returning(|_, _| {
        Ok((
            VeracruzClient::pub_read_cert(MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME)
                .unwrap()
                .0,
            MOCK_ATTESTATION_ENCLAVE_NAME.to_string(),
        ))
    });

    match load_client_cert_and_private_key(
        CLIENT_CERT_FILENAME,
        CLIENT_KEY_FILENAME,
        POLICY_FILENAME,
    ) {
        Err(s) => panic!(s),
        Ok((cert, pkey, policy)) => {

            let (enclave_cert, enclave_name) =
                crate::attestation::MockAttestation::attestation(&policy, &EnclavePlatform::Mock).unwrap();
            let policy_ciphersuite_string = policy.ciphersuite().as_str();
            assert!(VeracruzClient::pub_init_self_signed_cert_client_config(
                cert,
                pkey,
                enclave_cert,
                &enclave_name,
                policy_ciphersuite_string,
            )
            .is_ok());
        }
    }
}

#[test]
fn test_internal_init_self_signed_cert_client_config_invalid_ciphersuite() {
    // set up the attestation result as a mock object
    let handler = crate::attestation::MockAttestation::attestation_context();
    handler.expect().returning(|_, _| {
        Ok((
            VeracruzClient::pub_read_cert(MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME)
                .unwrap()
                .0,
            MOCK_ATTESTATION_ENCLAVE_NAME.to_string(),
        ))
    });

    match load_client_cert_and_private_key(
        CLIENT_CERT_FILENAME,
        CLIENT_KEY_FILENAME,
        POLICY_FILENAME,
    ) {
        Err(s) => panic!(s),
        Ok((cert, pkey, policy)) => {
            let (enclave_cert, enclave_name) =
                crate::attestation::MockAttestation::attestation(&policy, &EnclavePlatform::Mock).unwrap();
            let policy_ciphersuite_string = "WRONG CIPHERSUITE";
            assert!(VeracruzClient::pub_init_self_signed_cert_client_config(
                cert,
                pkey,
                enclave_cert,
                &enclave_name,
                policy_ciphersuite_string,
            )
            .is_err());
        }
    }
}

/// Auxiliary function: read policy file
fn read_policy(fname: &str) -> Result<String, VeracruzClientError> {
    let policy_string = std::fs::read_to_string(fname)?;
    Ok(policy_string.clone())
}

/// Auxiliary function: apply functor to all the policy file (json file) in the path
fn iterate_over_policy(path: &str, f: fn(Result<String, VeracruzClientError>) -> ()) {
    let test_collateral_path = Path::new(path);
    for entry in test_collateral_path
        .read_dir()
        .expect(&format!("invalid path:{}", path))
    {
        if let Ok(entry) = entry {
            if let Some(extension_str) = entry
                .path()
                .extension()
                .and_then(|extension_name| extension_name.to_str())
            {
                // iterate over all the json file
                if extension_str.eq_ignore_ascii_case("json") {
                    let policy_path = entry.path();
                    if let Some(policy) = policy_path.to_str() {
                        let policy = read_policy(policy);
                        f(policy);
                    }
                }
            }
        }
    }
}

#[test]
fn test_veracruz_client_new_succ() {
    // set up the attestation result as a mock object
    let handler = crate::attestation::MockAttestation::attestation_context();
    handler.expect().returning(|_, _| {
        Ok((
            VeracruzClient::pub_read_cert(MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME)
                .unwrap()
                .0,
            MOCK_ATTESTATION_ENCLAVE_NAME.to_string(),
        ))
    });

    iterate_over_policy("../test-collateral/", |policy| {

        assert!(policy.is_ok());
        let policy = policy.unwrap();
        assert!(VeracruzClient::new(CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, &policy, &EnclavePlatform::Mock).is_ok());
    });
}

#[test]
/// This function tests loading invalid policy.
/// Invalid or out-of-time certificate, and invalid or out-of-time enclave cert-time
fn test_veracruz_client_new_fail() {
    // set up the attestation result as a mock object
    let handler = crate::attestation::MockAttestation::attestation_context();
    handler.expect().returning(|_, _| {
        Ok((
            VeracruzClient::pub_read_cert(MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME)
                .unwrap()
                .0,
            MOCK_ATTESTATION_ENCLAVE_NAME.to_string(),
        ))
    });

    iterate_over_policy("../test-collateral/invalid_policy/", |policy| {
        if let Ok(policy) = policy {
            assert!(
                VeracruzClient::new(CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, &policy, &EnclavePlatform::Mock).is_err(),
                format!("{:?}", policy)
            );
        }
    });
}

#[test]
fn test_veracruz_client_new_unmatched_client_certificate() {
    // set up the attestation result as a mock object
    let handler = crate::attestation::MockAttestation::attestation_context();
    handler.expect().returning(|_, _| {
        Ok((
            VeracruzClient::pub_read_cert(MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME)
                .unwrap()
                .0,
            MOCK_ATTESTATION_ENCLAVE_NAME.to_string(),
        ))
    });

    let policy_json = std::fs::read_to_string(POLICY_FILENAME).unwrap();

    let rst = VeracruzClient::new(DATA_CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, &policy_json, &EnclavePlatform::Mock);
    assert!(rst.is_err());
}

#[test]
fn test_veracruz_client_new_unmatched_client_key() {
    // set up the attestation result as a mock object
    let handler = crate::attestation::MockAttestation::attestation_context();
    handler.expect().returning(|_, _| {
        Ok((
            VeracruzClient::pub_read_cert(MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME)
                .unwrap()
                .0,
            MOCK_ATTESTATION_ENCLAVE_NAME.to_string(),
        ))
    });

    let policy_json = std::fs::read_to_string(POLICY_FILENAME).unwrap();

    let rst = VeracruzClient::new(CLIENT_CERT_FILENAME, DATA_CLIENT_KEY_FILENAME, &policy_json, &EnclavePlatform::Mock);
    assert!(rst.is_err());
}

#[test]
fn test_veracruz_client_new_invalid_enclave_name() {
    // set up the attestation result as a mock object with an invalid host url
    let handler = crate::attestation::MockAttestation::attestation_context();
    handler.expect().returning(|_, _| {
        Ok((
            VeracruzClient::pub_read_cert(MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME)
                .unwrap()
                .0,
            "this is an invalid host url".to_string(),
        ))
    });

    let policy_json = std::fs::read_to_string(POLICY_FILENAME).unwrap();

    let rst = VeracruzClient::new(CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, &policy_json, &EnclavePlatform::Mock);
    assert!(rst.is_err());
}

#[actix_rt::test]
/// Test Durango's policy enforcement by setting up new Durango instances, and
/// then calling them using invalid client credentials for the policy
async fn veracruz_client_policy_violations() {
    // set up the attestation result as a mock object
    // This fakes the Attestation interface so we don't have to bring up a
    // proxy attestation server or communicate with IAS. This means that we are NOT
    // testing the attestation flow
    let handler = crate::attestation::MockAttestation::attestation_context();
    handler.expect().returning(|_policy, _target_platform| {
        Ok((
            VeracruzClient::pub_read_cert(MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME)
                .unwrap()
                .0,
            MOCK_ATTESTATION_ENCLAVE_NAME.to_string(),
        ))
    });

    let server_cert_filename = "../test-collateral/server_rsa_cert.pem";
    let server_key_filename = "../test-collateral/server_rsa_key.pem";
    let mut server_config = {
        let mut server_root_cert_store = rustls::RootCertStore::empty();
        let program_client_cert = VeracruzClient::pub_read_cert(PROGRAM_CLIENT_CERT_FILENAME).unwrap();
        let data_client_cert = VeracruzClient::pub_read_cert(DATA_CLIENT_CERT_FILENAME).unwrap();
        let result_client_cert = VeracruzClient::pub_read_cert(RESULT_CLIENT_CERT_FILENAME).unwrap();
        server_root_cert_store.add(&program_client_cert).unwrap();
        server_root_cert_store.add(&data_client_cert).unwrap();
        server_root_cert_store.add(&result_client_cert).unwrap();
        rustls::ServerConfig::new(rustls::AllowAnyAuthenticatedClient::new(
            server_root_cert_store,
        ))
    };
    let server_cert = VeracruzClient::pub_read_cert(server_cert_filename).unwrap();
    let server_priv_key = {
        let key_buffer = VeracruzClient::pub_read_all_bytes_in_file(server_key_filename).unwrap();
        let mut cursor = std::io::Cursor::new(key_buffer);
        let rsa_keys = rustls::internal::pemfile::rsa_private_keys(&mut cursor)
            .expect("file contains invalid rsa private key");
        rsa_keys[0].clone()
    };
    server_config.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());
    server_config
        .set_single_cert(vec![server_cert.clone()], server_priv_key)
        .expect("bad certificate/private key");
    server_config.ciphersuites = rustls::ALL_CIPHERSUITES.to_vec(); // TODO: Choose one ciphersuite
    server_config.versions = vec![rustls::ProtocolVersion::TLSv1_2];

    let mut server_session =
        rustls::ServerSession::new(&std::sync::Arc::new(server_config.clone()));

    let server_url = format!("localhost:3016");
    let server_loop_handle = policy_server_loop(&mut server_session, &server_url);

    let client_loop_handle = policy_client_loop();

    let _tj_ret = futures::try_join!(server_loop_handle, client_loop_handle);
}

async fn policy_client_loop() -> Result<(), VeracruzClientError> {
    let policy_json = std::fs::read_to_string(TRIPLE_POLICY_FILENAME).unwrap(); // TODO: Use a different policy file?

    let mut data_client = VeracruzClient::new(
        DATA_CLIENT_CERT_FILENAME,
        DATA_CLIENT_KEY_FILENAME,
        &policy_json,
        &EnclavePlatform::Mock,
    )?;

    let fake_data = vec![0xde, 0xad, 0xbe, 0xef];
    let sp_ret = data_client.send_program(&fake_data.to_vec());
    match sp_ret {
        Err(VeracruzClientError::InvalidRoleError(_, _))
        | Err(VeracruzClientError::InvalidClientCertificateError(_)) => (),
        _otherwise => panic!(),
    }

    let mut program_client = VeracruzClient::new(
        PROGRAM_CLIENT_CERT_FILENAME,
        PROGRAM_CLIENT_KEY_FILENAME,
        &policy_json,
        &EnclavePlatform::Mock,
    )?;

    let sd_ret = program_client.send_data(&fake_data.to_vec());
    match sd_ret {
        Err(VeracruzClientError::InvalidRoleError(_, _))
        | Err(VeracruzClientError::InvalidClientCertificateError(_)) => (),
        _otherwise => panic!(),
    }

    let gr_ret = program_client.get_results();
    match gr_ret {
        Err(VeracruzClientError::InvalidRoleError(_, _))
        | Err(VeracruzClientError::InvalidClientCertificateError(_)) => (),
        _otherwise => panic!(),
    }

    Err(VeracruzClientError::DirectMessage(format!(
        "returning error so try_join will terminate the server loop"
    )))
}

#[test]
#[ignore]
fn veracruz_client_session() {
    let server_cert_filename = "../test-collateral/server_rsa_cert.pem";
    let server_key_filename = "../test-collateral/server_rsa_key.pem";

    let server_cert = {
        let mut cert_file =
            std::fs::File::open(server_cert_filename).expect("Cannot open cert file for reading");
        let mut cert_buffer = std::vec::Vec::new();
        cert_file.read_to_end(&mut cert_buffer).unwrap();
        let mut cursor = std::io::Cursor::new(cert_buffer);
        let certs = rustls::internal::pemfile::certs(&mut cursor).unwrap();
        assert!(certs.len() > 0);
        certs[0].clone()
    };

    let server_priv_key = {
        let mut key_file =
            std::fs::File::open(server_key_filename).expect("Cannot open key file for reading");
        let mut key_buffer = std::vec::Vec::new();
        key_file.read_to_end(&mut key_buffer).unwrap();
        let mut cursor = std::io::Cursor::new(key_buffer);
        let rsa_keys = rustls::internal::pemfile::rsa_private_keys(&mut cursor)
            .expect("file contains invalid rsa private key");
        rsa_keys[0].clone()
    };

    let policy_json = std::fs::read_to_string(POLICY_FILENAME).unwrap();

    let mut _veracruz_client =
        crate::veracruz_client::VeracruzClient::new(CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, &policy_json, &EnclavePlatform::Mock)
            .unwrap();

    let client_cert = {
        let mut cert_file =
            std::fs::File::open(CLIENT_CERT_FILENAME).expect("Cannot open cert file for reading");
        let mut cert_buffer = std::vec::Vec::new();
        cert_file.read_to_end(&mut cert_buffer).unwrap();
        let mut cursor = std::io::Cursor::new(cert_buffer);
        let certs = rustls::internal::pemfile::certs(&mut cursor).unwrap();
        assert!(certs.len() > 0);
        certs[0].clone()
    };

    let mut server_root_cert_store = rustls::RootCertStore::empty();
    server_root_cert_store.add(&client_cert).unwrap();
    let mut server_config = rustls::ServerConfig::new(rustls::AllowAnyAuthenticatedClient::new(
        server_root_cert_store,
    ));
    server_config.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());
    server_config
        .set_single_cert(vec![server_cert.clone()], server_priv_key)
        .expect("bad certificate/private key");
    server_config.ciphersuites = rustls::ALL_CIPHERSUITES.to_vec(); // TODO: Choose one ciphersuite
    server_config.versions = vec![rustls::ProtocolVersion::TLSv1_2];
}

/// simple index handler
#[post("/mexico_city")]
async fn mc(session: Session, req: HttpRequest) -> Result<HttpResponse, actix_web::Error> {
    println!("mexico_city:{:?}", req);
    // session
    let mut counter = 1;
    if let Some(count) = session.get::<i32>("counter")? {
        println!("SESSION value: {}", count);
        counter = count + 1;
    }

    // set counter to session
    session.set("counter", counter)?;

    Ok(HttpResponse::build(StatusCode::NOT_FOUND)
        .content_type("text/html; charset=utf-8")
        .body(format!("Not found, so why you looking?")))
}

async fn policy_server_loop(
    _server_sess: &mut dyn rustls::Session,
    server_url: &str,
) -> Result<(), VeracruzClientError> {
    HttpServer::new(|| App::new().service(mc))
        .bind(server_url)
        .unwrap()
        .run()
        .await
        .map_err(|err| {
            VeracruzClientError::DirectMessage(format!("HttpServer failed to run:{:?}", err))
        })?;
    Ok(())
}

#[allow(dead_code)]
fn client_loop(
    tx: std::sync::mpsc::Sender<Vec<u8>>,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    session: &mut crate::veracruz_client::VeracruzClient,
) {
    let one_tenth_sec = std::time::Duration::from_millis(100);
    // The client initiates the handshake
    let message = String::from("Client Hello");
    session
        .pub_send(&message.into_bytes())
        .expect("Failed to send data");
    loop {
        let received = rx.try_recv();
        let mut received_buffer: Vec<u8> = Vec::new();
        if received.is_ok() {
            received_buffer = received.unwrap();
        }
        let output = session.pub_process(received_buffer).unwrap();
        match output {
            Some(output_data) => {
                if output_data.len() > 0 {
                    // output data needs to be sent to server
                    tx.send(output_data).unwrap();
                }
            }
            None => (),
        }

        // see if there's any actual data to read
        match session.pub_get_data().unwrap() {
            Some(x) => {
                let received_str = std::string::String::from_utf8(x).unwrap();
                assert_eq!(received_str, "Server Hello");
                break;
            }
            None => (),
        }
        std::thread::sleep(one_tenth_sec);
    }
}
