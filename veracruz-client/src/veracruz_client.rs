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
use anyhow::{anyhow, Result};
use bincode;
use log::{error, info};
use mbedtls::{alloc::List, pk::Pk, ssl::Context, x509::Certificate};
use policy_utils::{parsers::enforce_leading_backslash, policy::Policy, Platform};
use std::{
    io::{Read, Write},
    path::Path,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};
use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;

/// VeracruzClient struct. The remote_session_id is shared between
/// VeracruzClient and InsecureConnection so that it is available from
/// VeracruzClient methods and can also be updated by the
/// InsecureConnection methods invoked by mbedtls. Although we do not
/// expect multiple threads to be involved, since the compiler can not
/// check this, it is safer to use a Mutex.
pub struct VeracruzClient {
    tls_context: Context<InsecureConnection>,
    // The default should be ZERO
    remote_session_id: Arc<AtomicU32>,
    policy: Policy,
    policy_hash: String,
}

/// This is the structure given to mbedtls and used for reading and
/// writing cyphertext, using the standard Read and Write traits.
struct InsecureConnection {
    read_buffer: Vec<u8>,
    veracruz_server_url: String,
    // The default should be ZERO
    remote_session_id: Arc<AtomicU32>,
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
        let mut combined_data =
            bincode::serialize(&self.remote_session_id.load(Ordering::SeqCst)).unwrap();
        assert_eq!(combined_data.len(), 4);
        combined_data.extend_from_slice(&data);
        let addr = self.veracruz_server_url.to_string();
        let mut socket = std::net::TcpStream::connect(addr)?;
        socket.write_all(&combined_data)?;
        socket.shutdown(std::net::Shutdown::Write)?;
        let mut body = vec![];
        socket.read_to_end(&mut body)?;

        // We received a response ...
        if body.len() > 0 {
            if body.len() < 4 {
                return Err(err("bad session id"));
            }
            // If it was not empty, update the remote_session_id ...
            let received_session_id = bincode::deserialize(&body).unwrap();
            self.remote_session_id
                .store(received_session_id, Ordering::SeqCst);
            // And append response data to the read_buffer.
            self.read_buffer.extend_from_slice(&body[4..]);
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
    pub(crate) fn read_all_bytes_in_file<P: AsRef<Path>>(filename: P) -> Result<Vec<u8>> {
        let mut file = std::fs::File::open(filename)?;
        let mut buffer = std::vec::Vec::new();
        match file.read_to_end(&mut buffer) {
            Ok(_num) => (),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(err) => return Err(err.into()),
        }

        Ok(buffer)
    }

    /// Provide file path.
    /// Read the certificate in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    pub(crate) fn read_cert<P: AsRef<Path>>(filename: P) -> Result<List<Certificate>> {
        let mut buffer = VeracruzClient::read_all_bytes_in_file(filename)?;
        buffer.push(b'\0');
        let cert_vec = Certificate::from_pem_multiple(&buffer)?;
        if cert_vec.iter().count() == 1 {
            Ok(cert_vec)
        } else {
            Err(anyhow!(VeracruzClientError::UnexpectedCertificate))
        }
    }

    /// Provide file path.
    /// Read the private in the file.
    /// Return Ok(vec) if succ
    /// Otherwise return Err(msg) with the error message as String
    pub(crate) fn read_private_key<P: AsRef<Path>>(filename: P) -> Result<Pk> {
        let mut buffer = VeracruzClient::read_all_bytes_in_file(filename)?;
        buffer.push(b'\0');
        let pkey_vec = Pk::from_private_key(
            &mut mbedtls::rng::CtrDrbg::new(Arc::new(mbedtls::rng::OsEntropy::new()), None)?,
            &buffer,
            None,
        )?;
        Ok(pkey_vec)
    }

    /// Check the validity of client_cert:
    /// parse the certificate and match it with the public key generated from the private key;
    /// check if the certificate is valid in term of time.
    fn check_certificate_validity<P: AsRef<Path>>(
        client_cert_filename: P,
        public_key: &mut Pk,
    ) -> Result<()> {
        // Read and parse certificate.
        let mut buffer = VeracruzClient::read_all_bytes_in_file(&client_cert_filename)?;
        buffer.push(b'\0');
        let mut cert = Certificate::from_pem(&buffer)?;

        // Compare public keys as DER.
        let cert_public_key_der = cert.public_key_mut().write_public_der_vec()?;
        let public_key_der = public_key.write_public_der_vec()?;
        if cert_public_key_der != public_key_der {
            return Err(anyhow!(VeracruzClientError::UnexpectedKey));
        }

        // Check validity period.
        #[cfg(features = "std")]
        {
            use veracruz_utils::csr::generate_x509_time_now;

            let not_before = cert.not_before()?.to_x509_time();
            let not_after = cert.not_after()?.to_x509_time();
            let now = generate_x509_time_now();
            if now < not_before || now > not_after {
                return Err(anyhow!(VeracruzClientError::UnexpectedCertificate));
            }
        }

        Ok(())
    }

    /// Load the client certificate and key, and the global policy, which contains information
    /// about the enclave.
    /// Attest the enclave.
    pub fn new<P1: AsRef<Path>, P2: AsRef<Path>>(
        client_cert_filename: P1,
        client_key_filename: P2,
        policy_json: &str,
    ) -> Result<VeracruzClient> {
        let policy = Policy::from_json(policy_json)?;
        let policy_hash = policy
            .policy_hash()
            .ok_or(anyhow!(VeracruzClientError::UnexpectedPolicy))?
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
    ) -> Result<VeracruzClient> {
        let client_cert = Self::read_cert(&client_cert_filename)?;
        let mut client_priv_key = Self::read_private_key(&client_key_filename)?;

        // check if the certificate is valid
        Self::check_certificate_validity(&client_cert_filename, &mut client_priv_key)?;

        let proxy_service_cert = {
            let mut certs_pem = policy.proxy_service_cert().clone();
            certs_pem.push('\0');
            let certs = Certificate::from_pem_multiple(certs_pem.as_bytes())?;
            certs
        };

        use mbedtls::ssl::config::{Config, Endpoint, Preset, Transport, Version};
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_min_version(Version::Tls1_3)?;
        config.set_max_version(Version::Tls1_3)?;
        let policy_ciphersuite = veracruz_utils::lookup_ciphersuite(policy.ciphersuite().as_str())
            .ok_or(anyhow!(VeracruzClientError::UnexpectedCiphersuite))?;
        let cipher_suites: Vec<i32> = vec![policy_ciphersuite.into(), 0];
        config.set_ciphersuites(Arc::new(cipher_suites));
        let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
        let rng = Arc::new(mbedtls::rng::CtrDrbg::new(entropy, None)?);
        config.set_rng(rng);
        config.set_ca_list(Arc::new(proxy_service_cert), None);
        config.push_cert(Arc::new(client_cert), Arc::new(client_priv_key))?;
        let mut ctx = Context::new(Arc::new(config));
        let remote_session_id = Arc::new(AtomicU32::new(0));
        let conn = InsecureConnection {
            read_buffer: vec![],
            veracruz_server_url: policy.veracruz_server_url().to_string(),
            remote_session_id: remote_session_id.clone(),
        };
        ctx.establish(conn, None)?;

        Ok(VeracruzClient {
            tls_context: ctx,
            remote_session_id: remote_session_id.clone(),
            policy,
            policy_hash,
        })
    }

    /// A general pattern of the request, which lift the `serialize_functor` to a request to
    /// veracruz and parse the response.
    pub fn request_functor<P: AsRef<Path>>(
        &mut self,
        path: P,
        data: &[u8],
        serialize_functor: fn(&[u8], &str) -> transport_protocol::TransportProtocolResult,
    ) -> Result<transport_protocol::RuntimeManagerResponse> {
        let path = enforce_leading_backslash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_data = serialize_functor(data, &path)?;
        let response = self.send(&serialized_data)?;

        let parsed_response = transport_protocol::parse_runtime_manager_response(
            Some(self.remote_session_id.load(Ordering::SeqCst)),
            &response,
        )?;
        let status = parsed_response.get_status();
        match status {
            transport_protocol::ResponseStatus::SUCCESS => Ok(parsed_response),
            _ => Err(anyhow!(VeracruzClientError::ResponseStatus(status))),
        }
    }

    /// Request to write `data` to the `path` from the beginning.
    pub fn write_file<P: AsRef<Path>>(&mut self, path: P, data: &[u8]) -> Result<()> {
        self.request_functor(path, data, transport_protocol::serialize_write_file)?;
        Ok(())
    }

    /// Request to append `data` to the `path`.
    pub fn append_file<P: AsRef<Path>>(&mut self, path: P, data: &[u8]) -> Result<()> {
        self.request_functor(path, data, transport_protocol::serialize_append_file)?;
        Ok(())
    }

    /// Check the policy and runtime hashes, and request the veracruz to execute the program at the
    /// remote `path`.
    pub fn request_compute<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u8>> {
        let parsed_response = self.request_functor(path, &[], |_, path| {
            transport_protocol::serialize_request_result(path)
        })?;

        if !parsed_response.has_result() {
            return Err(anyhow!(VeracruzClientError::ResponseNoResult));
        }
        Ok(parsed_response.get_result().data.clone())
    }

    /// Check the policy and runtime hashes, and read the result at the remote `path`.
    pub fn read_file<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u8>> {
        let parsed_response = self.request_functor(path, &[], |_, path| {
            transport_protocol::serialize_read_file(path)
        })?;

        if !parsed_response.has_result() {
            return Err(anyhow!(VeracruzClientError::ResponseNoResult));
        }
        Ok(parsed_response.get_result().data.clone())
    }

    /// Indicate the veracruz to shutdown.
    pub fn request_shutdown(&mut self) -> Result<()> {
        self.request_functor("", &[], |_, _| {
            transport_protocol::serialize_request_shutdown()
        })?;
        Ok(())
    }

    /// Request the hash of the remote policy and check if it matches.
    pub fn check_policy_hash(&mut self) -> Result<()> {
        let parsed_response = self.request_functor("", &[], |_, _| {
            transport_protocol::serialize_request_policy_hash()
        })?;

        let received_hash = std::str::from_utf8(&parsed_response.get_policy_hash().data)?;
        if self.policy_hash != received_hash {
            Err(anyhow!(VeracruzClientError::UnexpectedPolicy))
        } else {
            Ok(())
        }
    }

    /// Check if the hash `received` matches those in the policy.
    fn compare_runtime_hash(&self, received: &[u8]) -> Result<()> {
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
        Err(anyhow!(VeracruzClientError::UnexpectedRuntimeHash))
    }

    /// Request the hash of the remote veracruz runtime and check if it matches.
    pub fn check_runtime_hash(&self) -> Result<()> {
        let certs = self.tls_context.peer_cert()?;
        if certs.iter().count() != 1 {
            return Err(anyhow!(VeracruzClientError::NoPeerCertificates));
        }
        let cert = certs
            .ok_or(anyhow!(VeracruzClientError::UnexpectedCertificate))?
            .iter()
            .nth(0)
            .ok_or(anyhow!(VeracruzClientError::UnexpectedCertificate))?;
        let extensions = cert.extensions()?;
        // check for OUR extension
        let data = veracruz_utils::find_extension(extensions, &VERACRUZ_RUNTIME_HASH_EXTENSION_ID)
            .ok_or({
                error!("Our extension is not present. This should be fatal");
                anyhow!(VeracruzClientError::RuntimeHashExtensionMissing)
            })?;
        info!("Certificate extension present.");
        self.compare_runtime_hash(&data).map_err(|err| {
            error!("Runtime hash mismatch: {}.", err);
            anyhow!(err)
        })
    }

    /// Send the data to the runtime_manager path on the Veracruz server
    /// and return the response.
    pub(crate) fn send(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.tls_context.write_all(&data)?;
        let mut response = vec![];
        match self.tls_context.read_to_end(&mut response) {
            Ok(_) => (),
            // Suppress the following err
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(err) => return Err(anyhow!(err)),
        };
        Ok(response)
    }
}
