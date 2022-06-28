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
use mbedtls::alloc::List;
use mbedtls::x509::Certificate;
use policy_utils::{parsers::enforce_leading_backslash, policy::Policy, Platform};
use std::{
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};
use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;

/// VeracruzClient struct. The remote_session_id is shared between
/// VeracruzClient and InsecureConnection so that it is available from
/// VeracruzClient methods and can also be updated by the
/// InsecureConnection methods invoked by mbedtls. Although we do not
/// expect multiple threads to be involved, since the compiler can not
/// check this, it is safer to use a Mutex.
pub struct VeracruzClient {
    tls_context: mbedtls::ssl::Context<InsecureConnection>,
    remote_session_id: Arc<Mutex<Option<u32>>>,
    policy: Policy,
    policy_hash: String,
}

/// This is the structure given to mbedtls and used for reading and
/// writing cyphertext, using the standard Read and Write traits.
struct InsecureConnection {
    read_buffer: Vec<u8>,
    veracruz_server_url: String,
    remote_session_id: Arc<Mutex<Option<u32>>>,
}

impl Read for InsecureConnection {
    fn read(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        // Return as much data from the read_buffer as fits.
        let n = std::cmp::min(data.len(), self.read_buffer.len());
        if n == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "InsecureConnection Read",
            ))
        } else {
            data[0..n].clone_from_slice(&self.read_buffer[0..n]);
            self.read_buffer = self.read_buffer[n..].to_vec();
            Ok(n)
        }
    }
}

impl Write for InsecureConnection {
    fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        // To convert any error to a std::io error:
        let err = |t| std::io::Error::new(std::io::ErrorKind::Other, t);

        // Send all the data to the server.
        let string_data = base64::encode(&data);
        let combined_string = format!(
            "{:} {:}",
            self.remote_session_id
                .lock()
                .map_err(|_| err("lock failed"))?
                .unwrap_or(0),
            string_data
        );
        let dest_url = format!("http://{:}/runtime_manager", self.veracruz_server_url,);
        // Spawn a separate thread so that we can use reqwest::blocking.
        let body = std::thread::spawn(move || {
            let client_build = reqwest::blocking::ClientBuilder::new()
                .build()
                .map_err(|_| err("reqwest new"))?;
            let ret = client_build
                .post(dest_url)
                .body(combined_string)
                .send()
                .map_err(|_| err("reqwest send"))?;
            if ret.status() != reqwest::StatusCode::OK {
                return Err(err("reqwest bad status"));
            }
            Ok(ret.text().map_err(|_| err("reqwest text"))?)
        })
        .join()
        .map_err(|_| err("join failed"))??;
        // We received a response ...
        let body_items = body.split_whitespace().collect::<Vec<&str>>();
        if !body_items.is_empty() {
            // If it was not empty, update the remote_session_id ...
            let received_session_id = body_items[0]
                .parse::<u32>()
                .map_err(|_| err("bad session id"))?;
            *self
                .remote_session_id
                .lock()
                .map_err(|_| err("lock failed"))? = Some(received_session_id);
            // And append response data to the read_buffer.
            for item in body_items.iter().skip(1) {
                let this_body_data = base64::decode(item).map_err(|_| err("base64::decode"))?;
                self.read_buffer.extend_from_slice(&this_body_data)
            }
        }
        // Return value to indicate that we handled all the data.
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
    fn read_cert<P: AsRef<Path>>(
        filename: P,
    ) -> Result<List<mbedtls::x509::Certificate>, VeracruzClientError> {
        let mut buffer = VeracruzClient::read_all_bytes_in_file(filename)?;
        buffer.push(b'\0');
        let cert_vec = Certificate::from_pem_multiple(&buffer)
            .map_err(|_| VeracruzClientError::TLSUnspecifiedError)?;
        if cert_vec.iter().count() == 1 {
            Ok(cert_vec)
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
    ) -> Result<mbedtls::pk::Pk, VeracruzClientError> {
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

        let proxy_service_cert = {
            let mut certs_pem = policy.proxy_service_cert().clone();
            certs_pem.push('\0');
            let certs = Certificate::from_pem_multiple(certs_pem.as_bytes()).map_err(|_| {
                VeracruzClientError::X509ParserError("Certificate::from_pem_multiple".to_string())
            })?;
            certs
        };
        let mut config = mbedtls::ssl::Config::new(
            mbedtls::ssl::config::Endpoint::Client,
            mbedtls::ssl::config::Transport::Stream,
            mbedtls::ssl::config::Preset::Default,
        );
        config.set_min_version(mbedtls::ssl::config::Version::Tls1_2)?;
        config.set_max_version(mbedtls::ssl::config::Version::Tls1_2)?;
        let policy_ciphersuite = veracruz_utils::lookup_ciphersuite(policy.ciphersuite().as_str())
            .ok_or_else(|| {
                VeracruzClientError::TLSInvalidCiphersuiteError(policy.ciphersuite().to_string())
            })?;
        let cipher_suites: Vec<i32> = vec![policy_ciphersuite.into(), 0];
        config.set_ciphersuites(Arc::new(cipher_suites));
        let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
        let rng = Arc::new(mbedtls::rng::CtrDrbg::new(entropy, None)?);
        config.set_rng(rng);
        config.set_ca_list(Arc::new(proxy_service_cert), None);
        config.push_cert(Arc::new(client_cert), Arc::new(client_priv_key))?;
        let mut ctx = mbedtls::ssl::Context::new(Arc::new(config));
        let remote_session_id = Arc::new(Mutex::new(Some(0)));
        let conn = InsecureConnection {
            read_buffer: vec![],
            veracruz_server_url: policy.veracruz_server_url().to_string(),
            remote_session_id: Arc::clone(&remote_session_id),
        };
        ctx.establish(conn, None)?;

        Ok(VeracruzClient {
            tls_context: ctx,
            remote_session_id: Arc::clone(&remote_session_id),
            policy,
            policy_hash,
        })
    }

    /// A general pattern of the request, which lift the `serialize_functor` to a request to
    /// veracruz and parse the response.
    pub async fn request_functor<P: AsRef<Path>>(
        &mut self,
        path: P,
        data: &[u8],
        serialize_functor: fn(&[u8], &str) -> transport_protocol::TransportProtocolResult,
    ) -> Result<transport_protocol::RuntimeManagerResponse, VeracruzClientError> {
        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_data = serialize_functor(data, &path)?;
        let response = self.send(&serialized_data).await?;

        let parsed_response = transport_protocol::parse_runtime_manager_response(
            *self
                .remote_session_id
                .lock()
                .map_err(|_| VeracruzClientError::LockFailed)?,
            &response,
        )?;
        let status = parsed_response.get_status();
        match status {
            transport_protocol::ResponseStatus::SUCCESS => Ok(parsed_response),
            _ => Err(VeracruzClientError::ResponseError("Response", status)),
        }
    }

    /// Request to write `data` to the `path` from the beginning.
    pub async fn write_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        data: &[u8],
    ) -> Result<(), VeracruzClientError> {
        self.request_functor(path, data, transport_protocol::serialize_write_file)
            .await?;
        Ok(())
    }

    /// Request to append `data` to the `path`.
    pub async fn append_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        data: &[u8],
    ) -> Result<(), VeracruzClientError> {
        self.request_functor(path, data, transport_protocol::serialize_append_file)
            .await?;
        Ok(())
    }

    /// Check the policy and runtime hashes, and request the veracruz to execute the program at the
    /// remote `path`.
    pub async fn request_compute<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<Vec<u8>, VeracruzClientError> {
        let parsed_response = self
            .request_functor(path, &[], |_, path| {
                transport_protocol::serialize_request_result(path)
            })
            .await?;

        if !parsed_response.has_result() {
            return Err(VeracruzClientError::VeracruzServerResponseNoResultError);
        }
        Ok(parsed_response.get_result().data.clone())
    }

    /// Check the policy and runtime hashes, and read the result at the remote `path`.
    pub async fn read_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<Vec<u8>, VeracruzClientError> {
        let parsed_response = self
            .request_functor(path, &[], |_, path| {
                transport_protocol::serialize_read_file(path)
            })
            .await?;

        if !parsed_response.has_result() {
            return Err(VeracruzClientError::VeracruzServerResponseNoResultError);
        }
        Ok(parsed_response.get_result().data.clone())
    }

    /// Indicate the veracruz to shutdown.
    pub async fn request_shutdown(&mut self) -> Result<(), VeracruzClientError> {
        self
            .request_functor("", &[], |_, _| {
                transport_protocol::serialize_request_shutdown()
            })
            .await?;
        Ok(())
    }

    /// Request the hash of the remote policy and check if it matches.
    pub async fn check_policy_hash(&mut self) -> Result<(), VeracruzClientError> {
        let parsed_response = self
            .request_functor("", &[], |_, _| {
                transport_protocol::serialize_request_policy_hash()
            })
            .await?;

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
    pub fn check_runtime_hash(&self) -> Result<(), VeracruzClientError> {
        let certs = self.tls_context.peer_cert()?;
        if certs.iter().count() != 1 {
            return Err(VeracruzClientError::NoPeerCertificatesError);
        }
        let cert = certs
            .ok_or(VeracruzClientError::UnexpectedCertificateError)?
            .iter()
            .nth(0)
            .ok_or(VeracruzClientError::UnexpectedCertificateError)?;
        let extensions = cert.extensions()?;
        // check for OUR extension
        match veracruz_utils::find_extension(extensions, &VERACRUZ_RUNTIME_HASH_EXTENSION_ID) {
            None => {
                error!("Our extension is not present. This should be fatal");
                Err(VeracruzClientError::RuntimeHashExtensionMissingError)
            }
            Some(data) => {
                info!("Certificate extension present.");
                match self.compare_runtime_hash(&data) {
                    Ok(_) => {
                        info!("Runtime hash matches.");
                        Ok(())
                    }
                    Err(err) => {
                        error!("Runtime hash mismatch: {}.", err);
                        Err(err)
                    }
                }
            }
        }
    }

    /// Send the data to the runtime_manager path on the Veracruz server
    /// and return the response.
    async fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, VeracruzClientError> {
        self.tls_context.write_all(&data)?;
        let mut response = vec![];
        match self.tls_context.read_to_end(&mut response) {
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => 0,
            x => x?,
        };
        Ok(response)
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
    ) -> Result<List<Certificate>, VeracruzClientError> {
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
}
