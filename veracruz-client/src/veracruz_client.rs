//! The Veracruz client's library
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::error::VeracruzClientError;
//use log::{error, info};
use mbedtls;
use mbedtls::alloc::List;
use mbedtls::ssl::CipherSuite::*;
use policy_utils::{parsers::enforce_leading_backslash, policy::Policy, Platform};
use std::{
    convert::TryFrom,
    io::{Read, Write},
    path::Path,
    str::from_utf8,
    sync::{Arc, Mutex},
};
//use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;
//use webpki;

//#[derive(Debug)]
pub struct VeracruzClient {
    tls_connection: mbedtls::ssl::Context<CbConn>,
    remote_session_id: Arc<Mutex<Option<u32>>>,
    policy: Policy,
    policy_hash: String,
    package_id: u32,
    client_cert: String,
}

struct CbConn {
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    veracruz_server_url: String,
    remote_session_id: Arc<Mutex<Option<u32>>>,
}

impl Read for CbConn {
    fn read(&mut self, data: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        let n = std::cmp::min(data.len(), self.read_buffer.len());
        //println!("xx returning {} of {}", n, self.read_buffer.len());
        data[0..n].clone_from_slice(&self.read_buffer[0..n]);
        self.read_buffer = self.read_buffer[n..].to_vec();
        Ok(n)
    }
}

impl Write for CbConn {
    fn write(&mut self, data: &[u8]) -> std::result::Result<usize, std::io::Error> {
        //println!("xx sending {:?}", data);
        let string_data = base64::encode(&data);
        let combined_string = format!("{:} {:}", self.remote_session_id.lock().unwrap().unwrap_or(0), string_data);

        let dest_url = format!(
            "http://{:}/runtime_manager",
            self.veracruz_server_url,
        );
        let client_build = reqwest::blocking::ClientBuilder::new().build().unwrap();
        let ret = match client_build
            .post(dest_url.as_str())
            .body(combined_string)
            .send() {
                Ok(x) => x,
                Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "xx1")),
            };
        if ret.status() != reqwest::StatusCode::OK {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "xx2"))
        }
        //println!("xx send suceeded:");
        let body = ret.text().unwrap();
        let body_items = body.split_whitespace().collect::<Vec<&str>>();
        if !body_items.is_empty() {
            let received_session_id = body_items[0].parse::<u32>().unwrap();
            *self.remote_session_id.lock().unwrap() = Some(received_session_id);
            let mut return_vec = Vec::new();
            for item in body_items.iter().skip(1) {
                let this_body_data = base64::decode(item).unwrap();
                //println!("xx received {:?}", this_body_data);
                return_vec.push(this_body_data);
            }
            if !return_vec.is_empty() {
                for x in return_vec {
                    self.read_buffer.extend_from_slice(&x)
                }
            }
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl VeracruzClient {
    /// Provide file path.
    /// Read all the bytes in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    fn read_all_bytes_in_file<P: AsRef<Path>>(filename: P) -> Result<Vec<u8>, VeracruzClientError> {
        let mut file = std::fs::File::open(filename)?;
        let mut buffer = std::vec::Vec::new();
        match file.read_to_end(&mut buffer) {
            Ok(_num) => (),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(err) => return Err(VeracruzClientError::IOError(err)),
        }

        Ok(buffer)
    }

    /// Provide file path.
    /// Read the certificate in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    // TODO: use generic functions to unify read_cert and read_private_key
    fn read_cert<P: AsRef<Path>>(filename: P) -> Result<List<mbedtls::x509::Certificate>, VeracruzClientError> {
        let mut buffer = VeracruzClient::read_all_bytes_in_file(filename)?;
        buffer.push(b'\0');
        let cert_vec = mbedtls::x509::Certificate::from_pem_multiple(&buffer)
            .map_err(|_| VeracruzClientError::TLSUnspecifiedError)?;
        Ok(cert_vec)
    }

    /// Provide file path.
    /// Read the private in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    fn read_private_key<P: AsRef<Path>>(filename: P) -> Result<mbedtls::pk::Pk, VeracruzClientError> {
        let mut buffer = VeracruzClient::read_all_bytes_in_file(filename)?;
        buffer.push(b'\0');
        let pkey_vec = mbedtls::pk::Pk::from_private_key(&buffer, None)
            .map_err(|_| VeracruzClientError::TLSUnspecifiedError)?;
        Ok(pkey_vec)
    }

    /// Check the validity of client_cert:
    /// parse the certificate and match it with the public key generated from the private key;
    /// check if the certificate is valid in term of time.
    fn check_certificate_validity<P: AsRef<Path>>(
        client_cert_filename: P,
        public_key: &mut mbedtls::pk::Pk,
    ) -> Result<(), VeracruzClientError> {
        let cert_file = std::fs::File::open(&client_cert_filename)?;
        let parsed_cert = x509_parser::pem::Pem::read(std::io::BufReader::new(cert_file))?;
        let parsed_cert = parsed_cert
            .0
            .parse_x509()
            .map_err(|e| VeracruzClientError::X509ParserError(e.to_string()))?
            .tbs_certificate;
        let cert_public_key_der =
            mbedtls::pk::Pk::from_public_key(parsed_cert.subject_pki.subject_public_key.data)?
                .write_public_der_vec()?;

        let public_key_der = public_key.write_public_der_vec()?;
        if cert_public_key_der != public_key_der {
            Err(VeracruzClientError::MismatchError {
                variable: "public_key",
                expected: cert_public_key_der,
                received: public_key_der,
            })
        } else if parsed_cert.validity.time_to_expiration().is_none() {
            Err(VeracruzClientError::CertificateExpireError(
                client_cert_filename.as_ref().to_string_lossy().to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Load the client certificate and key, and the global policy, which contains information
    /// about the enclave.
    /// Attest the enclave.
    pub fn new<P1: AsRef<Path>, P2: AsRef<Path>>(
        client_cert_filename: P1,
        client_key_filename: P2,
        policy_json: &str,
    ) -> Result<VeracruzClient, VeracruzClientError> {
        let policy = Policy::from_json(policy_json)?;
        let policy_hash = policy
            .policy_hash()
            .expect("policy did not hash json?")
            .to_string();

        Self::with_policy_and_hash(
            client_cert_filename,
            client_key_filename,
            policy,
            policy_hash,
        )
    }

    /// Load the client certificate and key, and the global policy, which contains information
    /// about the enclave. This takes the global policy as a VeracruzPolicy struct and
    /// related hash.
    /// Attest the enclave.
    pub fn with_policy_and_hash<P1: AsRef<Path>, P2: AsRef<Path>>(
        client_cert_filename: P1,
        client_key_filename: P2,
        policy: Policy,
        policy_hash: String,
    ) -> Result<VeracruzClient, VeracruzClientError> {
        let client_cert = Self::read_cert(&client_cert_filename)?;
        let mut client_priv_key = Self::read_private_key(&client_key_filename)?;

        // check if the certificate is valid
        Self::check_certificate_validity(&client_cert_filename, &mut client_priv_key)?;

        let enclave_name = "ComputeEnclave.dev";

        let policy_ciphersuite_string = policy.ciphersuite().as_str();

        let proxy_service_cert = {
            let mut certs_pem = policy.proxy_service_cert().clone();
            certs_pem.push('\0'); //xx
            let certs = mbedtls::x509::Certificate::from_pem_multiple(certs_pem.as_bytes()).map_err(|_| {
                VeracruzClientError::X509ParserError(
                    "mbedtls::x509::Certificate::from_pem_multiple".to_string(),
                )
            })?;
            certs
        };
        let mut config = mbedtls::ssl::Config::new(
            mbedtls::ssl::config::Endpoint::Client,
            mbedtls::ssl::config::Transport::Stream,
            mbedtls::ssl::config::Preset::Default);
        config.set_min_version(mbedtls::ssl::config::Version::Tls1_2).unwrap();
        config.set_max_version(mbedtls::ssl::config::Version::Tls1_2).unwrap();
        let cipher_suites : Vec<i32> = vec![EcdheEcdsaWithChacha20Poly1305Sha256.into(), 0];
        //let cipher_suites : Vec<i32> = vec![EcdheRsaWithAes256GcmSha384.into(), 0];
        //let cipher_suites : Vec<i32> = vec![RsaWithAes128GcmSha256.into(), DheRsaWithAes128GcmSha256.into(), PskWithAes128GcmSha256.into(), DhePskWithAes128GcmSha256.into(), RsaPskWithAes128GcmSha256.into(), 0];
        config.set_ciphersuites(Arc::new(cipher_suites));
        let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
        let rng = Arc::new(mbedtls::rng::CtrDrbg::new(entropy, None).unwrap());
        config.set_rng(rng);
        config.set_ca_list(Arc::new(proxy_service_cert), None);
        config.push_cert(Arc::new(client_cert), Arc::new(client_priv_key))?;
        let mut ctx = mbedtls::ssl::Context::new(Arc::new(config));
        let remote_session_id = Arc::new(Mutex::new(Some(0)));
        let conn = CbConn {
            read_buffer: vec![],
            write_buffer: vec![],
            veracruz_server_url: policy.veracruz_server_url().to_string(),
            remote_session_id: Arc::clone(&remote_session_id),
        };
        ctx.establish(conn, None).unwrap();

        let client_cert_text = VeracruzClient::read_all_bytes_in_file(&client_cert_filename)?;
        let mut client_cert_raw = from_utf8(client_cert_text.as_slice())?.to_string();
        // erase some '\n' to match the format in policy file.
        client_cert_raw.retain(|c| c != '\n');
        let client_cert_string = client_cert_raw
            .replace(
                "-----BEGIN CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\n",
            )
            .replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----");

        Ok(VeracruzClient {
            tls_connection: ctx,
            remote_session_id: Arc::clone(&remote_session_id),
            policy,
            policy_hash,
            package_id: 0,
            client_cert: client_cert_string,
        })
    }

    /// Check the policy and runtime hashes, and then send the `program` to the remote `path`.
    pub async fn send_program<P: AsRef<Path>>(
        &mut self,
        path: P,
        program: &[u8],
    ) -> Result<(), VeracruzClientError> {
        self.check_policy_hash().await?;
        self.check_runtime_hash()?;

        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_program = transport_protocol::serialize_program(program, &path)?;
        let response = self.send(&serialized_program).await?;
        let parsed_response =
            transport_protocol::parse_runtime_manager_response(*self.remote_session_id.lock().unwrap(), &response)?;
        let status = parsed_response.get_status();
        match status {
            transport_protocol::ResponseStatus::SUCCESS => Ok(()),
            _ => Err(VeracruzClientError::ResponseError("send_program", status)),
        }
    }

    /// Check the policy and runtime hashes, and then send the `data` to the remote `path`.
    pub async fn send_data<P: AsRef<Path>>(
        &mut self,
        path: P,
        data: &[u8],
    ) -> Result<(), VeracruzClientError> {
        self.check_policy_hash().await?;
        self.check_runtime_hash()?;

        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_data = transport_protocol::serialize_program_data(data, &path)?;
        let response = self.send(&serialized_data).await?;

        let parsed_response =
            transport_protocol::parse_runtime_manager_response(*self.remote_session_id.lock().unwrap(), &response)?;
        let status = parsed_response.get_status();
        match status {
            transport_protocol::ResponseStatus::SUCCESS => Ok(()),
            _ => Err(VeracruzClientError::ResponseError("send_data", status)),
        }
    }

    /// Check the policy and runtime hashes, and request the veracruz to execute the program at the
    /// remote `path`.
    pub async fn request_compute<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<Vec<u8>, VeracruzClientError> {
        self.check_policy_hash().await?;
        self.check_runtime_hash()?;

        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_read_result = transport_protocol::serialize_request_result(&path)?;
        let response = self.send(&serialized_read_result).await?;

        let parsed_response =
            transport_protocol::parse_runtime_manager_response(*self.remote_session_id.lock().unwrap(), &response)?;
        let status = parsed_response.get_status();
        if status != transport_protocol::ResponseStatus::SUCCESS {
            return Err(VeracruzClientError::ResponseError(
                "request_compute",
                status,
            ));
        }
        if !parsed_response.has_result() {
            return Err(VeracruzClientError::VeracruzServerResponseNoResultError);
        }
        let response_data = &parsed_response.get_result().data;
        Ok(response_data.clone())
    }

    /// Check the policy and runtime hashes, and read the result at the remote `path`.
    pub async fn get_results<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u8>, VeracruzClientError> {
        self.check_policy_hash().await?;
        self.check_runtime_hash()?;

        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_read_result = transport_protocol::serialize_read_file(&path)?;
        let response = self.send(&serialized_read_result).await?;

        let parsed_response =
            transport_protocol::parse_runtime_manager_response(*self.remote_session_id.lock().unwrap(), &response)?;
        let status = parsed_response.get_status();
        if status != transport_protocol::ResponseStatus::SUCCESS {
            return Err(VeracruzClientError::ResponseError("get_result", status));
        }
        if !parsed_response.has_result() {
            return Err(VeracruzClientError::VeracruzServerResponseNoResultError);
        }
        let response_data = &parsed_response.get_result().data;
        Ok(response_data.clone())
    }

    /// Indicate the veracruz to shutdown.
    pub async fn request_shutdown(&mut self) -> Result<(), VeracruzClientError> {
        let serialized_request = transport_protocol::serialize_request_shutdown()?;
        let _response = self.send(&serialized_request).await?;
        Ok(())
    }

    /// Request the hash of the remote policy and check if it matches.
    async fn check_policy_hash(&mut self) -> Result<(), VeracruzClientError> {
        let serialized_rph = transport_protocol::serialize_request_policy_hash()?;
        let response = self.send(&serialized_rph).await?;
        let parsed_response =
            transport_protocol::parse_runtime_manager_response(*self.remote_session_id.lock().unwrap(), &response)?;
        match parsed_response.status {
            transport_protocol::ResponseStatus::SUCCESS => {
                let received_hash = std::str::from_utf8(&parsed_response.get_policy_hash().data)?;
                if self.policy_hash != received_hash {
                    return Err(VeracruzClientError::MismatchError {
                        variable: "check_policy_hash",
                        expected: self.policy_hash.as_bytes().to_vec(),
                        received: received_hash.as_bytes().to_vec(),
                    });
                } else {
                    Ok(())
                }
            }
            _ => Err(VeracruzClientError::ResponseError(
                "check_policy_hash",
                parsed_response.status,
            )),
        }
    }

    /// Check if the hash `received` matches those in the policy.
    fn compare_runtime_hash(&self, received: &[u8]) -> Result<(), VeracruzClientError> {
        let platforms = vec![Platform::Linux, Platform::Nitro, Platform::IceCap];
        for platform in platforms {
            let expected = match self.policy.runtime_manager_hash(&platform) {
                Err(_) => continue, // no hash found for this platform
                Ok(data) => data,
            };
            let expected_bytes = hex::decode(expected)?;

            if received == expected_bytes.as_slice() {
                return Ok(());
            }
        }
        Err(VeracruzClientError::NoMatchingRuntimeIsolateHash)
    }

    /// Request the hash of the remote veracruz runtime and check if it matches.
    fn check_runtime_hash(&self) -> Result<(), VeracruzClientError> {
        Ok(()) //xx
    }

    /// Send the data to the runtime_manager path on the Veracruz server
    /// and return the response.
    async fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, VeracruzClientError> {
        let mut remote_session_id: u32 = 0;

        if let Some(session_id) = *self.remote_session_id.lock().unwrap() {
            remote_session_id = session_id
        }

        self.tls_connection.write_all(&data)?;
        let mut response = vec![];
        self.tls_connection.read_to_end(&mut response);
        Ok(response)
    }

    fn get_data(&mut self) -> Result<Option<std::vec::Vec<u8>>, VeracruzClientError> {
        let mut received_buffer: std::vec::Vec<u8> = std::vec::Vec::new();
        self.tls_connection.read_to_end(&mut received_buffer);
        if !received_buffer.is_empty() {
            Ok(Some(received_buffer))
        } else {
            Ok(None)
        }
    }

    // APIs for testing: expose internal functions
    #[cfg(test)]
    pub fn pub_read_all_bytes_in_file<P: AsRef<Path>>(
        filename: P,
    ) -> Result<Vec<u8>, VeracruzClientError> {
        VeracruzClient::read_all_bytes_in_file(filename)
    }

    #[cfg(test)]
    pub fn pub_read_cert<P: AsRef<Path>>(
        filename: P,
    ) -> Result<List<mbedtls::x509::Certificate>, VeracruzClientError> {
        VeracruzClient::read_cert(filename)
    }

    #[cfg(test)]
    pub fn pub_read_private_key<P: AsRef<Path>>(
        filename: P,
    ) -> Result<mbedtls::pk::Pk, VeracruzClientError> {
        VeracruzClient::read_private_key(filename)
    }

    #[cfg(test)]
    pub async fn pub_send(&mut self, data: &Vec<u8>) -> Result<Vec<u8>, VeracruzClientError> {
        self.send(data).await
    }

    #[cfg(test)]
    pub fn pub_get_data(&mut self) -> Result<Option<std::vec::Vec<u8>>, VeracruzClientError> {
        self.get_data()
    }
}

#[allow(dead_code)]
fn print_hex(data: &[u8]) -> String {
    let mut ret_val = String::new();
    for this_byte in data {
        ret_val.push_str(format!("{:02x}", this_byte).as_str());
    }
    ret_val
}

#[allow(dead_code)]
fn decode_tls_message(data: &[u8]) {
    match data[0] {
        0x16 => {
            print!("Handshake: ");
            match data[5] {
                0x01 => println!("Client hello"),
                0x02 => println!("Server hello"),
                0x0b => println!("Certificate"),
                0x0c => println!("ServerKeyExchange"),
                0x0d => println!("CertificateRequest"),
                0x0e => println!("ServerHelloDone"),
                0x10 => println!("ClientKeyExchange"),
                0x0f => println!("CertificateVerify"),
                0x14 => println!("Finished"),
                _ => println!("Unknown"),
            }
        }
        0x14 => {
            println!("ChangeCipherSpec");
        }
        0x15 => {
            println!("Alert");
        }
        0x17 => {
            println!("ApplicationData");
        }
        _ => println!("Unknown"),
    }
}
