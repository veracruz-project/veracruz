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
const CLIENT_CERT_FILENAME: &'static str = "client_rsa_cert.pem";
const CLIENT_KEY_FILENAME: &'static str = "client_rsa_key.pem";

use crate::veracruz_client::*;
use std::{env, fs::File, io::prelude::*, io::Read, path::PathBuf, sync::Arc};

use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::{post, HttpRequest, HttpResponse};
use mbedtls::x509::Certificate;

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
    let rst = VeracruzClient::read_all_bytes_in_file(filename);
    assert!(rst.is_ok());
    let rst_content = rst.unwrap();
    assert_eq!(rst_content, content);
}

#[test]
fn test_internal_read_all_bytes_in_file_invalid_file() {
    assert!(VeracruzClient::read_all_bytes_in_file(data_dir("invalid_file")).is_err());
}

#[test]
fn test_internal_read_all_bytes_in_file_invalid_path() {
    assert!(VeracruzClient::read_all_bytes_in_file("invalid_path").is_err());
}

#[test]
fn test_internal_read_cert_succ() {
    assert!(VeracruzClient::read_cert(trust_path(CLIENT_CERT_FILENAME)).is_ok());
}

#[test]
fn test_internal_read_cert_invalid_certificate() {
    assert!(VeracruzClient::read_cert(trust_path(CLIENT_KEY_FILENAME)).is_err());
}

#[test]
fn test_internal_read_private_key_succ() {
    assert!(VeracruzClient::read_private_key(trust_path(CLIENT_KEY_FILENAME)).is_ok());
}

#[test]
fn test_internal_read_cert_invalid_private_key() {
    assert!(VeracruzClient::read_private_key(trust_path(CLIENT_CERT_FILENAME)).is_err());
}

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
        cert_buffer.push(b'\0');
        let certs = Certificate::from_pem_multiple(&cert_buffer).unwrap();
        assert!(certs.iter().count() == 1);
        certs
    };

    let server_priv_key = {
        let mut key_file =
            std::fs::File::open(server_key_filename).expect("Cannot open key file for reading");
        let mut key_buffer = std::vec::Vec::new();
        key_file.read_to_end(&mut key_buffer).unwrap();
        key_buffer.push(b'\0');
        let rsa_keys = mbedtls::pk::Pk::from_private_key(
            &mut mbedtls::rng::CtrDrbg::new(Arc::new(mbedtls::rng::OsEntropy::new()), None)
                .unwrap(),
            &key_buffer,
            None,
        )
        .expect("file contains invalid rsa private key");
        rsa_keys
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
        cert_buffer.push(b'\0');
        let certs = Certificate::from_pem_multiple(&cert_buffer).unwrap();
        assert!(certs.iter().count() == 1);
        certs
    };

    let mut config = mbedtls::ssl::Config::new(
        mbedtls::ssl::config::Endpoint::Server,
        mbedtls::ssl::config::Transport::Stream,
        mbedtls::ssl::config::Preset::Default,
    );
    config.set_ca_list(Arc::new(client_cert), None);
    config
        .set_min_version(mbedtls::ssl::config::Version::Tls1_2)
        .unwrap();
    config
        .set_max_version(mbedtls::ssl::config::Version::Tls1_2)
        .unwrap();
    config
        .push_cert(Arc::new(server_cert), Arc::new(server_priv_key))
        .unwrap();
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
    session.insert("counter", counter)?;

    Ok(HttpResponse::build(StatusCode::NOT_FOUND)
        .content_type("text/html; charset=utf-8")
        .body(format!("Not found, so why you looking?")))
}
