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
use log::{error, info};
use mbedtls::{alloc::List, pk::Pk, ssl::Context, x509::Certificate};
use policy_utils::{parsers::enforce_leading_slash, policy::Policy, Platform};
use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    sync::Arc,
};
use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;

/// VeracruzClient struct.
pub struct VeracruzClient {
    tls_context: Context<TcpStream>,
    policy: Policy,
    policy_hash: String,
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
        config.set_min_version(Version::Tls13)?;
        config.set_max_version(Version::Tls13)?;
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
        let socket = TcpStream::connect(policy.veracruz_server_url())?;
        ctx.establish(socket, None)?;

        Ok(VeracruzClient {
            tls_context: ctx,
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
        let path = enforce_leading_slash(
            path.as_ref()
                .to_str()
                .ok_or(VeracruzClientError::InvalidPath)?,
        );
        let serialized_data = serialize_functor(data, &path)?;
        let response = self.send(&serialized_data)?;

        let parsed_response = transport_protocol::parse_runtime_manager_response(None, &response)?;
        let status = parsed_response.status.enum_value_or_default();
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

    /// Request the veracruz to execute the program at the remote `path`.
    pub fn request_compute<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u8>> {
        let parsed_response = self.request_functor(path, &[], |_, path| {
            transport_protocol::serialize_request_result(path)
        })?;

        if !parsed_response.has_result() {
            return Err(anyhow!(VeracruzClientError::ResponseNoResult));
        }
        Ok(parsed_response.result().data.clone())
    }

    /// Request the veracruz to execute the program at the remote `path`.
    pub fn request_pipeline<P: AsRef<Path>>(&mut self, pipeline_id: P) -> Result<Vec<u8>> {
        let parsed_response = self.request_functor(pipeline_id, &[], |_, pipeline_id| {
            transport_protocol::serialize_request_pipeline(pipeline_id)
        })?;

        if !parsed_response.has_result() {
            return Err(anyhow!(VeracruzClientError::ResponseNoResult));
        }
        Ok(parsed_response.result().data.clone())
    }

    /// Check the policy and runtime hashes, and read the result at the remote `path`.
    pub fn read_file<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u8>> {
        let parsed_response = self.request_functor(path, &[], |_, path| {
            transport_protocol::serialize_read_file(path)
        })?;

        if !parsed_response.has_result() {
            return Err(anyhow!(VeracruzClientError::ResponseNoResult));
        }
        Ok(parsed_response.result().data.clone())
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

        let received_hash = std::str::from_utf8(&parsed_response.policy_hash().data)?;
        if self.policy_hash != received_hash {
            Err(anyhow!(VeracruzClientError::UnexpectedPolicy))
        } else {
            Ok(())
        }
    }

    /// Check if the hash `received` matches those in the policy.
    fn compare_runtime_hash(&self, received: &[u8]) -> Result<()> {
        let platforms = vec![Platform::Linux, Platform::Nitro];
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
        const PREFLEN: usize = transport_protocol::LENGTH_PREFIX_SIZE;
        let mut length_buffer = [0; PREFLEN];
        self.tls_context.read_exact(&mut length_buffer)?;
        let length = PREFLEN + u64::from_be_bytes(length_buffer) as usize;
        let mut response = length_buffer.to_vec();
        response.resize(length, 0);
        self.tls_context
            .read_exact(&mut response[PREFLEN..length])?;
        Ok(response)
    }
}
