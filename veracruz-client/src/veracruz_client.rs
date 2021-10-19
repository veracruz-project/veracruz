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
use ring::signature::KeyPair;
use rustls::Session;
use std::{
    path,
    io::{Read, Write},
    str::from_utf8,
};
use veracruz_utils::policy::policy::Policy;
use veracruz_utils::{platform::Platform, VERACRUZ_RUNTIME_HASH_EXTENSION_ID};
use webpki;

// Use Mockall for testing
#[cfg(feature = "mock")]
use crate::attestation::MockAttestation as AttestationHandler;

#[derive(Debug)]
pub struct VeracruzClient {
    tls_session: rustls::ClientSession,
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
    fn read_all_bytes_in_file<P>(filename: P) -> Result<Vec<u8>, VeracruzClientError>
    where
        P: AsRef<path::Path>
    {
        let mut file = std::fs::File::open(filename)?;
        let mut buffer = std::vec::Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    /// Provide file path.
    /// Read the certificate in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    // TODO: use generic functions to unify read_cert and read_private_key
    fn read_cert<P>(filename: P) -> Result<rustls::Certificate, VeracruzClientError>
    where
        P: AsRef<path::Path>
    {
        let buffer = VeracruzClient::read_all_bytes_in_file(filename)?;
        let mut cursor = std::io::Cursor::new(buffer);
        let cert_vec = rustls::internal::pemfile::certs(&mut cursor)
            .map_err(|_| VeracruzClientError::TLSUnspecifiedError)?;
        if cert_vec.len() == 1 {
            Ok(cert_vec[0].clone())
        } else {
            Err(VeracruzClientError::InvalidLengthError("cert_vec", 1))
        }
    }

    /// Provide file path.
    /// Read the private in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    fn read_private_key<P>(filename: P) -> Result<rustls::PrivateKey, VeracruzClientError>
    where
        P: AsRef<path::Path>
    {
        let buffer = VeracruzClient::read_all_bytes_in_file(filename)?;
        let mut cursor = std::io::Cursor::new(buffer);
        let pkey_vec = rustls::internal::pemfile::rsa_private_keys(&mut cursor)
            .map_err(|_| VeracruzClientError::TLSUnspecifiedError)?;
        if pkey_vec.len() == 1 {
            Ok(pkey_vec[0].clone())
        } else {
            Err(VeracruzClientError::InvalidLengthError("cert_vec", 1))
        }
    }

    /// If ``ciphersuite_string`` is a supported cipher suite,
    /// add it into ``client_config``.
    /// Otherwise return error message.
    fn set_up_client_ciphersuite(
        client_config: &mut rustls::ClientConfig,
        ciphersuite_string: &str,
    ) -> Result<(), VeracruzClientError> {
        client_config.ciphersuites.clear();

        let policy_ciphersuite =
            rustls::CipherSuite::lookup_value(ciphersuite_string).map_err(|_| {
                VeracruzClientError::TLSInvalidCyphersuiteError(ciphersuite_string.to_string())
            })?;
        let supported_ciphersuite = rustls::ALL_CIPHERSUITES
            .iter()
            .fold(None, |last_rst, avalabie| {
                last_rst.or(if avalabie.suite == policy_ciphersuite {
                    Some(avalabie)
                } else {
                    None
                })
            })
            .ok_or(VeracruzClientError::TLSUnsupportedCyphersuiteError(
                policy_ciphersuite,
            ))?;
        client_config.ciphersuites.push(supported_ciphersuite);
        return Ok(());
    }

    /// Check the validity of client_cert:
    /// parse the certificate and match it with the public key generated from the private key;
    /// check if the certificate is valid in term of time.
    fn check_certificate_validity<P>(
        client_cert_filename: P,
        public_key: &[u8],
    ) -> Result<(), VeracruzClientError>
    where
        P: AsRef<path::Path>
    {
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
    pub fn new<P1, P2>(
        client_cert_filename: P1,
        client_key_filename: P2,
        policy_json: &str,
    ) -> Result<VeracruzClient, VeracruzClientError>
    where
        P1: AsRef<path::Path>,
        P2: AsRef<path::Path>
    {
        let policy = Policy::from_json(&policy_json)?;
        let policy_hash = policy.policy_hash()
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
    pub fn with_policy_and_hash<P1, P2>(
        client_cert_filename: P1,
        client_key_filename: P2,
        policy: Policy,
        policy_hash: String,
    ) -> Result<VeracruzClient, VeracruzClientError>
    where
        P1: AsRef<path::Path>,
        P2: AsRef<path::Path>
    {
        let client_cert = Self::read_cert(&client_cert_filename)?;
        let client_priv_key = Self::read_private_key(&client_key_filename)?;

        // check if the certificate is valid
        let key_pair = ring::signature::RsaKeyPair::from_der(client_priv_key.0.as_slice())
            .map_err(|err| {
                VeracruzClientError::RingError(format!("from_der failed:{:?}", err))
            })?;
        Self::check_certificate_validity(&client_cert_filename, key_pair.public_key().as_ref())?;

        let enclave_name = "ComputeEnclave.dev";

        let policy_ciphersuite_string = policy.ciphersuite().as_str();

        let mut client_config = rustls::ClientConfig::new();
        let mut client_cert_vec = std::vec::Vec::new();
        client_cert_vec.push(client_cert);
        client_config.set_single_client_cert(client_cert_vec, client_priv_key);
        let proxy_service_cert = {
            let certs_pem = policy.proxy_service_cert();
            let certs = rustls::internal::pemfile::certs(&mut certs_pem.as_bytes())
                .map_err(|_| VeracruzClientError::X509ParserError(format!("pemfile::certs found not certificates")))?;
            certs[0].clone()
        };
        client_config.root_store.add(&proxy_service_cert)?;
        Self::set_up_client_ciphersuite(&mut client_config, &policy_ciphersuite_string)?;

        let dns_name = webpki::DNSNameRef::try_from_ascii_str(&enclave_name)?;
        let session = rustls::ClientSession::new(&std::sync::Arc::new(client_config), dns_name);
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
            tls_session: session,
            remote_session_id: None,
            policy: policy,
            policy_hash: policy_hash,
            package_id: 0,
            client_cert: client_cert_string,
        })
    }

    pub fn send_program(&mut self, file_name:&str, program: &Vec<u8>) -> Result<(), VeracruzClientError> {
        self.check_policy_hash()?;
        self.check_runtime_hash()?;

        let serialized_program = transport_protocol::serialize_program(&program, file_name)?;
        let response = self.send(&serialized_program)?;
        let parsed_response = transport_protocol::parse_runtime_manager_response(&response)?;
        let status = parsed_response.get_status();
        match status {
            transport_protocol::ResponseStatus::SUCCESS => return Ok(()),
            _ => {
                return Err(VeracruzClientError::ResponseError("send_program", status));
            }
        }
    }

    pub fn send_data(&mut self,file_name:&str, data: &Vec<u8>) -> Result<(), VeracruzClientError> {
        self.check_policy_hash()?;
        self.check_runtime_hash()?;
        let serialized_data = transport_protocol::serialize_program_data(&data, file_name)?;
        let response = self.send(&serialized_data)?;

        let parsed_response = transport_protocol::parse_runtime_manager_response(&response)?;
        let status = parsed_response.get_status();
        match status {
            transport_protocol::ResponseStatus::SUCCESS => return Ok(()),
            _ => {
                return Err(VeracruzClientError::ResponseError("send_data", status));
            }
        }
    }

    pub fn get_results(&mut self, file_name:&str) -> Result<Vec<u8>, VeracruzClientError> {
        self.check_policy_hash()?;
        self.check_runtime_hash()?;

        let serialized_read_result = transport_protocol::serialize_request_result(file_name)?;
        let response = self.send(&serialized_read_result)?;

        let parsed_response = transport_protocol::parse_runtime_manager_response(&response)?;
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

    pub fn request_shutdown(&mut self) -> Result<(), VeracruzClientError> {
        let serialized_request = transport_protocol::serialize_request_shutdown()?;
        let _response = self.send(&serialized_request)?;
        Ok(())
    }

    fn check_policy_hash(&mut self) -> Result<(), VeracruzClientError> {
        let serialized_rph = transport_protocol::serialize_request_policy_hash()?;
        let response = self.send(&serialized_rph)?;
        let parsed_response = transport_protocol::parse_runtime_manager_response(&response)?;
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

    fn compare_runtime_hash(&self, received: &[u8]) -> Result<(), VeracruzClientError> {
        let platforms = vec![Platform::SGX, Platform::TrustZone, Platform::Nitro, Platform::IceCap];
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

    fn check_runtime_hash(&self) -> Result<(), VeracruzClientError> {
        match self.tls_session.get_peer_certificates() {
            None => {
                return Err(VeracruzClientError::NoPeerCertificatesError);
            },
            Some(certs) => {
                let ee_cert = webpki::EndEntityCert::from(certs[0].as_ref())?;
                let ues = ee_cert.unrecognized_extensions();
                // check for OUR extension
                // The Extension is encoded using DER, which puts the first two
                // elements in the ID in 1 byte, and the rest get their own bytes
                // This encoding is specified in ITU Recommendation x.690, 
                // which is available here: https://www.itu.int/rec/T-REC-X.690-202102-I/en
                // but it's deep inside a PDF...
                let encoded_extension_id: [u8; 3] = [VERACRUZ_RUNTIME_HASH_EXTENSION_ID[0] * 40 + VERACRUZ_RUNTIME_HASH_EXTENSION_ID[1],
                                                     VERACRUZ_RUNTIME_HASH_EXTENSION_ID[2],
                                                     VERACRUZ_RUNTIME_HASH_EXTENSION_ID[3]];
                match ues.get(&encoded_extension_id[..]) {
                    None => {
                        println!("Our extension is not present. This should be fatal");
                        return Err(VeracruzClientError::RuntimeHashExtensionMissingError);
                    },
                    Some(data) => {
                        let extension_data = data.read_all(VeracruzClientError::UnableToReadError, |input| {
                            Ok(input.read_bytes_to_end())
                        })?;
                        match self.compare_runtime_hash(extension_data.as_slice_less_safe()) {
                            Ok(_) => return Ok(()),
                            Err(err) => {
                                // None of the hashes matched
                                println!("None of the hashes matched.");
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

        self.tls_session.write_all(&data[..])?;

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
        if input.len() > 0 && (!self.tls_session.is_handshaking() || self.tls_session.wants_read())
        {
            let mut slice = &input[..];
            self.tls_session.read_tls(&mut slice)?;

            self.tls_session.process_new_packets()?;
        }
        if self.tls_session.wants_write() {
            self.tls_session.write_tls(&mut output)?;
            ret_option = Some(output);
        }
        Ok(ret_option)
    }

    fn get_data(&mut self) -> Result<Option<std::vec::Vec<u8>>, VeracruzClientError> {
        let mut ret_val = None;
        let mut received_buffer: std::vec::Vec<u8> = std::vec::Vec::new();
        self.tls_session.process_new_packets()?;
        let read_received = self.tls_session.read_to_end(&mut received_buffer);
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

        let dest_url = format!("http://{:}/runtime_manager", self.policy.veracruz_server_url());
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
    pub fn pub_read_all_bytes_in_file<P>(filename: P) -> Result<Vec<u8>, VeracruzClientError>
    where
        P: AsRef<path::Path>
    {
        VeracruzClient::read_all_bytes_in_file(filename)
    }

    #[cfg(test)]
    pub fn pub_read_cert<P>(filename: P) -> Result<rustls::Certificate, VeracruzClientError>
    where
        P: AsRef<path::Path>
    {
        VeracruzClient::read_cert(filename)
    }

    #[cfg(test)]
    pub fn pub_read_private_key<P>(filename: P) -> Result<rustls::PrivateKey, VeracruzClientError>
    where
        P: AsRef<path::Path>
    {
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
