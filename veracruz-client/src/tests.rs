//! Client-specific tests
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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

const POLICY_FILENAME: &'static str = "single_client.json";
const TRIPLE_POLICY_FILENAME: &'static str = "triple_policy.json";
const CLIENT_CERT_FILENAME: &'static str = "client_rsa_cert.pem";
const CLIENT_KEY_FILENAME: &'static str = "client_rsa_key.pem";

const PROGRAM_CLIENT_CERT_FILENAME: &'static str = "program_client_cert.pem";
const PROGRAM_CLIENT_KEY_FILENAME: &'static str = "program_client_key.pem";

const DATA_CLIENT_CERT_FILENAME: &'static str = "data_client_cert.pem";
const DATA_CLIENT_KEY_FILENAME: &'static str = "data_client_key.pem";

const RESULT_CLIENT_CERT_FILENAME: &'static str = "result_client_cert.pem";

const MOCK_ATTESTATION_ENCLAVE_CERT_FILENAME: &'static str = "server_rsa_cert.pem";
const MOCK_ATTESTATION_ENCLAVE_NAME: &'static str = "localhost";

use crate::error::*;
use crate::veracruz_client::*;
use std::{
    env,
    fs::File,
    io::prelude::*,
    io::Read,
    path::{Path, PathBuf},
};

use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::{post, App, HttpRequest, HttpResponse, HttpServer};
use futures;

pub fn policy_path(filename: &str) -> PathBuf {
    PathBuf::from(env::var("VERACRUZ_POLICY_DIR").unwrap_or("../test-collateral".to_string()))
        .join(filename)
}
pub fn policy_directory() -> PathBuf {
    PathBuf::from(env::var("VERACRUZ_POLICY_DIR").unwrap_or("../test-collateral".to_string()))
}
pub fn trust_path(filename: &str) -> PathBuf {
    PathBuf::from(env::var("VERACRUZ_TRUST_DIR").unwrap_or("../test-collateral".to_string()))
        .join(filename)
}
pub fn data_dir(filename: &str) -> PathBuf {
    PathBuf::from(env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()))
        .join(filename)
}

#[test]
fn test_internal_read_all_bytes_in_file_succ() {
    let filename = "test.temp";
    let content = b"Hello, world!";
    if let Err(_) = File::create(filename).and_then(|mut file| file.write_all(content)) {
        panic!("cannot create test file: {}", filename);
    }
    let rst = VeracruzClient::pub_read_all_bytes_in_file(filename);
    assert!(rst.is_ok());
    let rst_content = rst.unwrap();
    assert_eq!(rst_content, content);
}

#[test]
fn test_internal_read_all_bytes_in_file_invalid_file() {
    assert!(VeracruzClient::pub_read_all_bytes_in_file(data_dir("invalid_file")).is_err());
}

#[test]
fn test_internal_read_all_bytes_in_file_invalid_path() {
    assert!(VeracruzClient::pub_read_all_bytes_in_file("invalid_path").is_err());
}

#[test]
fn test_internal_read_cert_succ() {
    assert!(VeracruzClient::pub_read_cert(trust_path(CLIENT_CERT_FILENAME)).is_ok());
}

#[test]
fn test_internal_read_cert_invalid_certificate() {
    assert!(VeracruzClient::pub_read_cert(trust_path(CLIENT_KEY_FILENAME)).is_err());
}

#[test]
fn test_internal_read_private_key_succ() {
    assert!(VeracruzClient::pub_read_private_key(trust_path(CLIENT_KEY_FILENAME)).is_ok());
}

#[test]
fn test_internal_read_cert_invalid_private_key() {
    assert!(VeracruzClient::pub_read_private_key(trust_path(CLIENT_CERT_FILENAME)).is_err());
}

/// Auxiliary function: read policy file
fn read_policy(fname: &str) -> Result<String, VeracruzClientError> {
    let policy_string = std::fs::read_to_string(fname)?;
    Ok(policy_string.clone())
}

/// Auxiliary function: apply functor to all the policy file (json file) in the path
fn iterate_over_policy(
    test_collateral_path: &Path,
    f: fn(Result<String, VeracruzClientError>) -> (),
) {
    for entry in test_collateral_path
        .read_dir()
        .expect(&format!("invalid path:{}", test_collateral_path.display()))
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

#[actix_rt::test]
#[should_panic]
/// Test client's policy enforcement by setting up new client instances, and
/// then calling them using invalid client credentials for the policy
/// TODO update this test case in the following possible options:
/// - checking if the client send data/program but vialoate the capabilities in the policy ?

#[test]
#[ignore]
fn veracruz_client_session() {
    let server_cert_filename = trust_path("server_rsa_cert.pem");
    let server_key_filename = trust_path("server_rsa_key.pem");

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

    let mut _veracruz_client = crate::veracruz_client::VeracruzClient::new(
        trust_path(CLIENT_CERT_FILENAME),
        trust_path(CLIENT_KEY_FILENAME),
        &policy_json,
    )
    .unwrap();

    let client_cert = {
        let mut cert_file = std::fs::File::open(trust_path(CLIENT_CERT_FILENAME))
            .expect("Cannot open cert file for reading");
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
#[post("/runtime_manager")]
async fn runtime_manager(
    session: Session,
    req: HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    println!("runtime_manager:{:?}", req);
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
    HttpServer::new(|| App::new().service(runtime_manager))
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
