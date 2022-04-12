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
use log::{error, info};
use policy_utils::{parsers::enforce_leading_backslash, policy::Policy, Platform};
use ring::signature::KeyPair;
use rustls::{
    Certificate,
    ClientConnection,
    PrivateKey
};
use rustls_pemfile;
use std::{
    convert::TryFrom,
    io::{Read, Write},
    path::Path,
    str::from_utf8,
};
use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;
use webpki;

#[derive(Debug)]
pub struct VeracruzClient {
    tls_connection: ClientConnection,
    remote_session_id: Option<u32>,
    policy: Policy,
    policy_hash: String,
    package_id: u32,
    client_cert: String,
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
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                ()
            },
            Err(err) => return Err(VeracruzClientError::IOError(err)),
        }

        Ok(buffer)
    }

    /// Provide file path.
    /// Read the certificate in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    // TODO: use generic functions to unify read_cert and read_private_key
    fn read_cert<P: AsRef<Path>>(filename: P) -> Result<rustls::Certificate, VeracruzClientError> {
        let buffer = VeracruzClient::read_all_bytes_in_file(filename)?;
        let mut cursor = std::io::Cursor::new(buffer);
        let cert_vec = rustls_pemfile::certs(&mut cursor)
            .map_err(|_| VeracruzClientError::TLSUnspecifiedError)?;
        if cert_vec.len() == 1 {
            Ok(Certificate(cert_vec[0].clone()))
        } else {
            Err(VeracruzClientError::InvalidLengthError("cert_vec", 1))
        }
    }

    /// Provide file path.
    /// Read the private in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    fn read_private_key<P: AsRef<Path>>(
        filename: P,
    ) -> Result<PrivateKey, VeracruzClientError> {
        let buffer = VeracruzClient::read_all_bytes_in_file(filename)?;
        let mut cursor = std::io::Cursor::new(buffer);
        let pkey_vec = rustls_pemfile::rsa_private_keys(&mut cursor)
            .map_err(|_| VeracruzClientError::TLSUnspecifiedError)?;
        if pkey_vec.len() == 1 {
            Ok(PrivateKey(pkey_vec[0].clone()))
        } else {
            Err(VeracruzClientError::InvalidLengthError("cert_vec", 1))
        }
    }

    /// Check the validity of client_cert:
    /// parse the certificate and match it with the public key generated from the private key;
    /// check if the certificate is valid in term of time.
    fn check_certificate_validity<P: AsRef<Path>>(
        client_cert_filename: P,
        public_key: &[u8],
    ) -> Result<(), VeracruzClientError> {
        let cert_file = std::fs::File::open(&client_cert_filename)?;
        let parsed_cert = x509_parser::pem::Pem::read(std::io::BufReader::new(cert_file))?;
        let parsed_cert = parsed_cert
            .0
            .parse_x509()
            .map_err(|e| VeracruzClientError::X509ParserError(e.to_string()))?
            .tbs_certificate;

        if parsed_cert.subject_pki.subject_public_key.data != public_key {
            Err(VeracruzClientError::MismatchError {
                variable: "public_key",
                expected: parsed_cert.subject_pki.subject_public_key.data.to_vec(),
                received: public_key.to_vec(),
            })
        } else if let None = parsed_cert.validity.time_to_expiration() {
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
        let policy = Policy::from_json(&policy_json)?;
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
        let client_priv_key = Self::read_private_key(&client_key_filename)?;

        // check if the certificate is valid
        let key_pair = ring::signature::RsaKeyPair::from_der(client_priv_key.0.as_slice())
            .map_err(|err| VeracruzClientError::RingError(format!("from_der failed:{:?}", err)))?;
        Self::check_certificate_validity(&client_cert_filename, key_pair.public_key().as_ref())?;

        let enclave_name = "ComputeEnclave.dev";

        let policy_ciphersuite_string = policy.ciphersuite().as_str();

        let proxy_service_cert = {
            let certs_pem = policy.proxy_service_cert();
            let certs =
                rustls_pemfile::certs(&mut certs_pem.as_bytes()).map_err(|_| {
                    VeracruzClientError::X509ParserError(format!(
                        "rustls_pemfile::certs found not certificates"
                    ))
                })?;
            certs[0].clone()
        };
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(&rustls::Certificate(proxy_service_cert))
            .map_err(|err| VeracruzClientError::WebpkiError(err))?;

        let policy_ciphersuite = veracruz_utils::lookup_ciphersuite(&policy_ciphersuite_string)
            .ok_or_else(|| VeracruzClientError::TLSInvalidCiphersuiteError(policy_ciphersuite_string.to_string()))?;

        let client_config = rustls::ClientConfig::builder()
            .with_cipher_suites(&[policy_ciphersuite])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS12])?
            .with_root_certificates(root_store)
            .with_single_cert([client_cert].to_vec(), client_priv_key)
            ?;

        let enclave_name_as_server = rustls::ServerName::try_from(enclave_name)
            .map_err(|err| VeracruzClientError::InvalidDnsNameError(err))?;
        let connection = ClientConnection::new(std::sync::Arc::new(client_config), enclave_name_as_server)?;
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
            tls_connection: connection,
            remote_session_id: None,
            policy: policy,
            policy_hash: policy_hash,
            package_id: 0,
            client_cert: client_cert_string,
        })
    }

    /// Check the policy and runtime hashes, and then send the `program` to the remote `path`.
    pub fn send_program<P: AsRef<Path>>(
        &mut self,
        path: P,
        program: &[u8],
    ) -> Result<(), VeracruzClientError> {
        self.check_policy_hash()?;
        self.check_runtime_hash()?;

        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_program = transport_protocol::serialize_program(&program, &path)?;
        let response = self.send(&serialized_program)?;
        let parsed_response =
            transport_protocol::parse_runtime_manager_response(self.remote_session_id, &response)?;
        let status = parsed_response.get_status();
        match status {
            transport_protocol::ResponseStatus::SUCCESS => return Ok(()),
            _ => {
                return Err(VeracruzClientError::ResponseError("send_program", status));
            }
        }
    }

    /// Check the policy and runtime hashes, and then send the `data` to the remote `path`.
    pub fn send_data<P: AsRef<Path>>(
        &mut self,
        path: P,
        data: &[u8],
    ) -> Result<(), VeracruzClientError> {
        self.check_policy_hash()?;
        self.check_runtime_hash()?;

        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_data = transport_protocol::serialize_program_data(&data, &path)?;
        let response = self.send(&serialized_data)?;

        let parsed_response =
            transport_protocol::parse_runtime_manager_response(self.remote_session_id, &response)?;
        let status = parsed_response.get_status();
        match status {
            transport_protocol::ResponseStatus::SUCCESS => return Ok(()),
            _ => {
                return Err(VeracruzClientError::ResponseError("send_data", status));
            }
        }
    }

    /// Check the policy and runtime hashes, and request the veracruz to execute the program at the
    /// remote `path`.
    pub fn request_compute<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<Vec<u8>, VeracruzClientError> {
        self.check_policy_hash()?;
        self.check_runtime_hash()?;

        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_read_result = transport_protocol::serialize_request_result(&path)?;
        let response = self.send(&serialized_read_result)?;

        let parsed_response =
            transport_protocol::parse_runtime_manager_response(self.remote_session_id, &response)?;
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
        return Ok(response_data.clone());
    }

    /// Check the policy and runtime hashes, and read the result at the remote `path`.
    pub fn get_results<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u8>, VeracruzClientError> {
        self.check_policy_hash()?;
        self.check_runtime_hash()?;

        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_read_result = transport_protocol::serialize_read_file(&path)?;
        let response = self.send(&serialized_read_result)?;

        let parsed_response =
            transport_protocol::parse_runtime_manager_response(self.remote_session_id, &response)?;
        let status = parsed_response.get_status();
        if status != transport_protocol::ResponseStatus::SUCCESS {
            return Err(VeracruzClientError::ResponseError("get_result", status));
        }
        if !parsed_response.has_result() {
            return Err(VeracruzClientError::VeracruzServerResponseNoResultError);
        }
        let response_data = &parsed_response.get_result().data;
        return Ok(response_data.clone());
    }

    /// Indicate the veracruz to shutdown.
    pub fn request_shutdown(&mut self) -> Result<(), VeracruzClientError> {
        let serialized_request = transport_protocol::serialize_request_shutdown()?;
        let _response = self.send(&serialized_request)?;
        Ok(())
    }

    /// Request the hash of the remote policy and check if it matches.
    fn check_policy_hash(&mut self) -> Result<(), VeracruzClientError> {
        let serialized_rph = transport_protocol::serialize_request_policy_hash()?;
        let response = self.send(&serialized_rph)?;
        let parsed_response =
            transport_protocol::parse_runtime_manager_response(self.remote_session_id, &response)?;
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
                    return Ok(());
                }
            }
            _ => {
                return Err(VeracruzClientError::ResponseError(
                    "check_policy_hash",
                    parsed_response.status,
                ));
            }
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

            if &received[..] == expected_bytes.as_slice() {
                return Ok(());
            }
        }
        return Err(VeracruzClientError::NoMatchingRuntimeIsolateHash);
    }

    /// Request the hash of the remote veracruz runtime and check if it matches.
    fn check_runtime_hash(&self) -> Result<(), VeracruzClientError> {
        match self.tls_connection.peer_certificates() {
            None => {
                return Err(VeracruzClientError::NoPeerCertificatesError);
            }
            Some(certs) => {
                let ee_cert = webpki::EndEntityCert::try_from(certs[0].as_ref())?;
                let ues = ee_cert.unrecognized_extensions();
                // check for OUR extension
                // The Extension is encoded using DER, which puts the first two
                // elements in the ID in 1 byte, and the rest get their own bytes
                // This encoding is specified in ITU Recommendation x.690,
                // which is available here: https://www.itu.int/rec/T-REC-X.690-202102-I/en
                // but it's deep inside a PDF...
                let encoded_extension_id: [u8; 3] = [
                    VERACRUZ_RUNTIME_HASH_EXTENSION_ID[0] * 40
                        + VERACRUZ_RUNTIME_HASH_EXTENSION_ID[1],
                    VERACRUZ_RUNTIME_HASH_EXTENSION_ID[2],
                    VERACRUZ_RUNTIME_HASH_EXTENSION_ID[3],
                ];
                match ues.get(&encoded_extension_id[..]) {
                    None => {
                        error!("Our extension is not present. This should be fatal");

                        return Err(VeracruzClientError::RuntimeHashExtensionMissingError);
                    }
                    Some(data) => {
                        info!("Certificate extension present.");

                        let extension_data = data
                            .read_all(VeracruzClientError::UnableToReadError, |input| {
                                Ok(input.read_bytes_to_end())
                            })?;

                        info!("Certificate extension extracted correctly.");

                        match self.compare_runtime_hash(extension_data.as_slice_less_safe()) {
                            Ok(_) => {
                                info!("Runtime hash matches.");

                                return Ok(());
                            }
                            Err(err) => {
                                error!("Runtime hash mismatch: {}.", err);

                                return Err(err);
                            }
                        }
                    }
                }
            }
        }
    }

    /// send the data to the runtime_manager path on the Veracruz server.
    // TODO: This function has return points scattered all over, making it very hard to follow
    fn send(&mut self, data: &Vec<u8>) -> Result<Vec<u8>, VeracruzClientError> {
        let mut enclave_session_id: u32 = 0;
        match self.remote_session_id {
            Some(session_id) => enclave_session_id = session_id,
            None => (),
        }

        self.tls_connection.writer().write_all(&data[..])?;

        let mut outgoing_data_vec = Vec::new();
        let outgoing_data = Vec::new();
        let outgoing_data_option = self.process(outgoing_data)?; // intentionally sending no data to process
        match outgoing_data_option {
            Some(outgoing_data) => outgoing_data_vec.push(outgoing_data),
            None => (),
        }

        let mut incoming_data_vec: Vec<Vec<u8>> = Vec::new();

        loop {
            for outgoing_data in &outgoing_data_vec {
                let incoming_data_option =
                    self.post_runtime_manager(enclave_session_id, &outgoing_data)?;
                match incoming_data_option {
                    Some((received_session_id, received_data_vec)) => {
                        enclave_session_id = received_session_id;
                        for received_data in received_data_vec {
                            incoming_data_vec.push(received_data);
                        }
                    }
                    None => (),
                }
            }

            outgoing_data_vec.clear();
            if incoming_data_vec.len() > 0 {
                for incoming_data in &incoming_data_vec {
                    let outgoing_data_option = self.process(incoming_data.to_vec())?;
                    match outgoing_data_option {
                        Some(outgoing_data) => {
                            outgoing_data_vec.push(outgoing_data);
                        }
                        None => (),
                    }
                }
                incoming_data_vec.clear();
            } else {
                // try process with no data to see if it wants to send
                let empty_vec = Vec::new();
                let outgoing_data_option = self.process(empty_vec)?;
                match outgoing_data_option {
                    Some(outgoing_data) => outgoing_data_vec.push(outgoing_data),
                    None => (),
                }
            }

            let plaintext_data_option = self.get_data()?;
            match plaintext_data_option {
                Some(plaintext_data) => {
                    self.remote_session_id = Some(enclave_session_id);

                    return Ok(plaintext_data);
                }
                None => (),
            }
        }
    }

    fn process(&mut self, input: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzClientError> {
        let mut ret_option = None;
        let mut output: std::vec::Vec<u8> = std::vec::Vec::new();
        if input.len() > 0 && (!self.tls_connection.is_handshaking() || self.tls_connection.wants_read())
        {
            let mut slice = &input[..];
            self.tls_connection.read_tls(&mut slice)?;

            self.tls_connection.process_new_packets()?;
        }
        if self.tls_connection.wants_write() {
            self.tls_connection.write_tls(&mut output)?;
            ret_option = Some(output);
        }
        Ok(ret_option)
    }

    fn get_data(&mut self) -> Result<Option<std::vec::Vec<u8>>, VeracruzClientError> {
        let mut ret_val = None;
        let mut received_buffer: std::vec::Vec<u8> = std::vec::Vec::new();
        self.tls_connection.process_new_packets()?;
        let read_received = match self.tls_connection.reader().read_to_end(&mut received_buffer) {
            Ok(num) => Ok(num),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                println!("session-manager::Would block");
                Ok(0)
            },
            Err(err) => Err(VeracruzClientError::IOError(err)),
        };
        if read_received.is_ok() && received_buffer.len() > 0 {
            ret_val = Some(received_buffer)
        }
        Ok(ret_val)
    }

    fn post_runtime_manager(
        &self,
        enclave_session_id: u32,
        data: &Vec<u8>,
    ) -> Result<Option<(u32, Vec<Vec<u8>>)>, VeracruzClientError> {
        let string_data = base64::encode(data);
        let combined_string = format!("{:} {:}", enclave_session_id, string_data);

        let dest_url = format!(
            "http://{:}/runtime_manager",
            self.policy.veracruz_server_url()
        );
        let client_build = reqwest::ClientBuilder::new().timeout(None).build()?;
        let mut ret = client_build
            .post(dest_url.as_str())
            .body(combined_string)
            .send()?;
        if ret.status() != reqwest::StatusCode::OK {
            return Err(VeracruzClientError::InvalidReqwestError(ret.status()));
        }
        let body = ret.text()?;

        let body_items = body.split_whitespace().collect::<Vec<&str>>();
        if body_items.len() > 0 {
            let received_session_id = body_items[0].parse::<u32>()?;
            let mut return_vec = Vec::new();
            for x in 1..body_items.len() {
                let this_body_data = base64::decode(&body_items[x])?;
                return_vec.push(this_body_data);
            }
            if return_vec.len() > 0 {
                Ok(Some((received_session_id, return_vec)))
            } else {
                Ok(None)
            }
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
    ) -> Result<rustls::Certificate, VeracruzClientError> {
        VeracruzClient::read_cert(filename)
    }

    #[cfg(test)]
    pub fn pub_read_private_key<P: AsRef<Path>>(
        filename: P,
    ) -> Result<PrivateKey, VeracruzClientError> {
        VeracruzClient::read_private_key(filename)
    }

    #[cfg(test)]
    pub fn pub_send(&mut self, data: &Vec<u8>) -> Result<Vec<u8>, VeracruzClientError> {
        self.send(data)
    }

    #[cfg(test)]
    pub fn pub_process(&mut self, input: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzClientError> {
        self.process(input)
    }

    #[cfg(test)]
    pub fn pub_get_data(&mut self) -> Result<Option<std::vec::Vec<u8>>, VeracruzClientError> {
        self.get_data()
    }
}

#[allow(dead_code)]
fn print_hex(data: &Vec<u8>) -> String {
    let mut ret_val = String::new();
    for this_byte in data {
        ret_val.push_str(format!("{:02x}", this_byte).as_str());
    }
    ret_val
}

#[allow(dead_code)]
fn decode_tls_message(data: &Vec<u8>) {
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
