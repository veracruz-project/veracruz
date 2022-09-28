//! Linux-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "linux")]
pub mod veracruz_server_linux {

    use crate::common::{VeracruzServer, VeracruzServerError, VeracruzServerResult};
    use data_encoding::HEXLOWER;
    use io_utils::{
        http::{HttpError, HttpResponse, post_string, send_proxy_attestation_server_start},
        tcp::{receive_message, send_message},
    };
    use log::{error, info};
    use nix::sys::signal;
    use nix::unistd::alarm;
    use policy_utils::policy::Policy;
    use rand::Rng;
    use std::{
        env,
        error::Error,
        fs::{self, File},
        io::Read,
        net::{Shutdown, TcpStream},
        os::unix::fs::PermissionsExt,
        process::{Child, Command, Stdio},
    };
    use tempfile::{self, TempDir};
    use transport_protocol::{
        parse_proxy_attestation_server_response, serialize_native_psa_attestation_token,
    };
    use veracruz_utils::runtime_manager_message::{
        RuntimeManagerRequest, RuntimeManagerResponse, Status,
    };
    use veracruz_utils::sha256::sha256;

    ////////////////////////////////////////////////////////////////////////////
    // Constants.
    ////////////////////////////////////////////////////////////////////////////

    /// The Runtime Manager binary (the enclave), included at compile time
    const RUNTIME_ENCLAVE_BINARY_IMAGE: &[u8] = include_bytes!(env!("RUNTIME_ENCLAVE_BINARY_PATH"));
    /// Delay (in seconds) before terminating this process with SIGALRM if
    /// the Runtime Manager has not yet started up.
    const RUNTIME_ENCLAVE_STARTUP_TIMEOUT: u32 = 30;
    /// IP address to use when communicating with the Runtime Manager enclave.
    const RUNTIME_MANAGER_ENCLAVE_ADDRESS: &str = "127.0.0.1";
    /// Minimum port number for the Runtime Manager enclave.
    const RUNTIME_MANAGER_ENCLAVE_PORT_MIN: i32 = 6000;
    /// Maximum port number for the Runtime Manager enclave.
    const RUNTIME_MANAGER_ENCLAVE_PORT_MAX: i32 = 6999;

    /// The protocol to use with the proxy attestation server.
    const PROXY_ATTESTATION_PROTOCOL: &str = "psa";

    /// A struct capturing all the metadata needed to start and communicate with
    /// the Linux root enclave.
    pub struct VeracruzServerLinux {
        /// A handle to the Runtime Manager enclave process.
        runtime_manager_process: Child,
        /// The socket used to communicate with the Runtime Manager enclave.
        runtime_manager_socket: TcpStream,
        /// Temporary dir where we store our image, this gets cleaned up when VeracruzServerLinux is dropped
        #[allow(dead_code)]
        runtime_enclave_binary_dir: TempDir,
    }

    impl VeracruzServerLinux {
        /// Returns `Ok(true)` iff further TLS data can be read from the socket
        /// connecting the Veracruz server and the Linux root enclave.
        /// Returns `Ok(false)` iff no further TLS data can be read.
        ///
        /// Returns an appropriate error if:
        ///
        /// 1. The request could not be serialized, or sent to the enclave.
        /// 2. The response could be not be received, or deserialized.
        /// 3. The response was received and deserialized correctly, but was of
        ///    an unexpected form.
        pub fn tls_data_needed(&mut self, session_id: u32) -> VeracruzServerResult<bool> {
            info!("Checking whether TLS data can be read from Runtime Manager enclave (with session: {}).", session_id);

            info!("Sending TLS data check message.");

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerRequest::GetTlsDataNeeded(session_id),
            )?;

            info!("TLS data check message successfully sent.");

            info!("Awaiting response...");

            let received: RuntimeManagerResponse =
                receive_message(&mut self.runtime_manager_socket)?;

            info!("Response received.");

            match received {
                RuntimeManagerResponse::TlsDataNeeded(response) => {
                    info!(
                        "Runtime Manager enclave can have further TLS data read: {}.",
                        response
                    );

                    Ok(response)
                }
                otherwise => {
                    error!(
                        "Runtime Manager enclave returned unexpected response.  Received: {:?}.",
                        otherwise
                    );

                    Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ))
                }
            }
        }

        /// Reads TLS data from the Runtime Manager enclave.  Implicitly assumes
        /// that the Runtime Manager enclave has more data to be read.  Returns
        /// `Ok((alive_status, buffer))` if more TLS data could be read from the
        /// enclave, where `buffer` is a buffer of TLS data and `alive_status`
        /// captures the status of the TLS connection.
        ///
        /// Returns an appropriate error if:
        ///
        /// 1. The TLS data request message cannot be serialized, or transmitted
        ///    to the enclave.
        /// 2. A response is not received back from the Enclave in response to
        ///    the message sent in (1) above, or the message cannot be
        ///    deserialized.
        /// 3. The Runtime Manager enclave sends back a message indicating that
        ///    it was not expecting further TLS data to be requested.
        pub fn read_tls_data(&mut self, session_id: u32) -> VeracruzServerResult<(bool, Vec<u8>)> {
            info!(
                "Reading TLS data from Runtime Manager enclave (with session: {}).",
                session_id
            );

            info!("Sending get TLS data message.");

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerRequest::GetTlsData(session_id),
            )?;

            info!("Get TLS data message successfully sent.");

            info!("Awaiting response...");

            let received: RuntimeManagerResponse =
                receive_message(&mut self.runtime_manager_socket)?;

            info!("Response received.");

            match received {
                RuntimeManagerResponse::TlsData(buffer, alive) => {
                    info!("{} bytes of TLS data received from Runtime Manager enclave (alive status: {}).", buffer.len(), alive);

                    Ok((alive, buffer))
                }
                otherwise => {
                    error!("Unexpected reply received back from Runtime Manager enclave.  Received: {:?}.", otherwise);

                    Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ))
                }
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Trait implementations.
    ////////////////////////////////////////////////////////////////////////////

    /// An implementation of the `Drop` trait that forcibly kills the runtime
    /// manager enclave, and closes the socket used for communicating with it, when
    /// a `VeracruzServerLinux` struct is about to go out of scope.
    impl Drop for VeracruzServerLinux {
        fn drop(&mut self) {
            info!("Dropping VeracruzServerLinux object, shutting down enclave...");
            if let Err(error) = self.shutdown_isolate() {
                error!(
                    "Failed to forcibly shutdown Runtime Manager enclave.  Error produced: {:?}.",
                    error
                );
            }
            info!("VeracruzServerLinux object killed.");
        }
    }

    impl VeracruzServer for VeracruzServerLinux {
        /// Creates a new instance of the `VeracruzServerLinux` type.
        fn new(policy: &str) -> VeracruzServerResult<Self>
        where
            Self: Sized,
        {
            // TODO: add in dummy measurement and attestation token issuance here
            // which will use fields from the JSON policy file.
            let policy_json = Policy::from_json(policy).map_err(|e| {
                error!(
                    "Failed to parse Veracruz policy file.  Error produced: {:?}.",
                    e
                );

                e
            })?;

            // temporary directory to store image
            let runtime_enclave_binary_dir = tempfile::tempdir()?;

            let runtime_enclave_binary_path = runtime_enclave_binary_dir
                .path()
                .join("runtime_enclave_binary");
            fs::write(&runtime_enclave_binary_path, RUNTIME_ENCLAVE_BINARY_IMAGE)?;

            // make sure our image is executable
            let mut runtime_enclave_binary_permissions =
                fs::metadata(&runtime_enclave_binary_path)?.permissions();
            runtime_enclave_binary_permissions.set_mode(0o500); // readable and executable by user is all we need
            fs::set_permissions(
                &runtime_enclave_binary_path,
                runtime_enclave_binary_permissions,
            )?;

            info!(
                "Computing measurement of runtime manager enclave (using binary {:?})",
                runtime_enclave_binary_path
            );

            let measurement = match File::open(&runtime_enclave_binary_path) {
                Ok(mut file) => {
                    let mut buffer = Vec::new();

                    if let Err(err) = file.read_to_end(&mut buffer) {
                        error!(
                            "Failed to read file: {:?}.  Error produced: {}.",
                            runtime_enclave_binary_path, err
                        );

                        return Err(VeracruzServerError::IOError(err));
                    }

                    let digest = sha256(&buffer);
                    HEXLOWER.encode(digest.as_ref())
                }
                Err(err) => {
                    error!("Failed to open file: {:?}.", &runtime_enclave_binary_path);
                    return Err(VeracruzServerError::IOError(err));
                }
            };

            info!(
                "Measurement {} computed for Runtime Manager enclave.",
                measurement
            );

            // Choose a port number at random (to reduce risk of collision
            // with another test that is still running).
            let port = rand::thread_rng()
                .gen_range(RUNTIME_MANAGER_ENCLAVE_PORT_MIN..RUNTIME_MANAGER_ENCLAVE_PORT_MAX + 1);
            info!(
                "Starting runtime manager enclave (using binary {:?} and port {})",
                runtime_enclave_binary_path, port
            );

            // Ignore SIGCHLD to avoid zombie processes.
            unsafe {
                signal::sigaction(
                    signal::Signal::SIGCHLD,
                    &signal::SigAction::new(
                        signal::SigHandler::SigIgn,
                        signal::SaFlags::empty(),
                        signal::SigSet::empty(),
                    ),
                )
                .expect("sigaction failed");
            }

            // Spawn the runtime manager.
            let mut runtime_manager_process = Command::new(runtime_enclave_binary_path)
                .arg("--port")
                .arg(format!("{}", port))
                .arg("--measurement")
                .arg(measurement)
                .arg("--write-nl")
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| {
                    error!(
                        "Failed to launch Runtime Manager enclave.  Error produced: {:?}.",
                        e
                    );

                    VeracruzServerError::IOError(e)
                })?;

            // Use a closure here so that we can catch any error and
            // terminate the runtime manager.
            let (received, runtime_manager_socket) = (|| {

            // Request SIGALRM after the specified time has elapsed.
            alarm::set(RUNTIME_ENCLAVE_STARTUP_TIMEOUT);
            let mut buf: [u8; 1] = [0];
            runtime_manager_process.stdout.take()
                .ok_or(VeracruzServerError::RuntimeManagerFailed)?
                .read_exact(&mut buf)?;
            alarm::cancel(); // Cancel the alarm.
            if buf[0] != b'\n' {
                return Err(VeracruzServerError::RuntimeManagerFailed);
            }

            let runtime_manager_address = format!(
                "{}:{}",
                RUNTIME_MANAGER_ENCLAVE_ADDRESS, port
            );

            info!(
                "Establishing connection with new Runtime Manager enclave on address: {}.",
                runtime_manager_address
            );

            let mut runtime_manager_socket = TcpStream::connect(&runtime_manager_address).map_err(|e| {
                error!("Failed to connect to Runtime Manager enclave at address {}.  Error produced: {}.", runtime_manager_address, e);

                VeracruzServerError::IOError(e)
            })?;

            // Configure TCP to flush outgoing buffers immediately. This reduces
            // latency when dealing with small packets
            let _ = runtime_manager_socket.set_nodelay(true);

            info!(
                "Connected to Runtime Manager enclave at address {}.",
                runtime_manager_address
            );

            info!("Sending proxy attestation 'start' message.");

            let proxy_attestation_server_url = policy_json.proxy_attestation_server_url();

            let (challenge_id, challenge) = send_proxy_attestation_server_start(
                proxy_attestation_server_url,
                PROXY_ATTESTATION_PROTOCOL,
            )
            .map_err(|e| {
                error!(
                    "Failed to start proxy attestation process.  Error received: {:?}.",
                    e
                );

                e
            })?;

            send_message(&mut runtime_manager_socket, &RuntimeManagerRequest::Attestation(challenge, challenge_id)).map_err(|e| {
                error!("Failed to send attestation message to runtime manager enclave.  Error returned: {:?}.", e);

                e
            })?;

            info!("Attestation message successfully sent to runtime manager enclave.");

            let received: RuntimeManagerResponse = receive_message(&mut runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to runtime manager enclave attestation message.  Error received: {:?}.", e);

                e
            })?;

            info!("Response to attestation message received from runtime manager enclave.");

            let (token, csr) = match received {
                RuntimeManagerResponse::AttestationData(token, csr) => {
                    info!("Response to attestation message successfully received.",);

                    (token, csr)
                }
                otherwise => {
                    error!(
                        "Unexpected response received from runtime manager enclave: {:?}.",
                        otherwise
                    );

                    return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ));
                }
            };

            info!("Requesting certificate chain from proxy attestation server.");

            let (root_cert, compute_cert) = {
                let req = serialize_native_psa_attestation_token(&token, &csr, challenge_id).map_err(|e| {
                    error!("Failed to serialize native PSA attestation token request.  Error received: {:?}.", e);

                    e
                })?;
                let req = base64::encode(&req);
                let url = format!("{}/PSA/AttestationToken", proxy_attestation_server_url);
                let resp = match post_string(&url, &req, None).map_err(|e| {
                        error!("Failed to send request to proxy attestation server (at URL {:?}).  Error received: {:?}.", url, e);

                        VeracruzServerError::HttpError(e)
                    })? {
                    HttpResponse::Ok(body) => body,
                    not_ok => {
                        error!("post buffer returned a non-Ok status code:{:?}", not_ok);
                        return Err(VeracruzServerError::HttpError(HttpError::HttpSuccess));
                    }
                };
                let resp = base64::decode(&resp).map_err(|e| {
                    error!("Failed to Base64 decode response from proxy attestation server.  Error received: {:?}.", e);

                    VeracruzServerError::Base64Error(e)
                })?;
                let pasr = parse_proxy_attestation_server_response(None, &resp).map_err(|e| {
                    error!("Failed to parse reponse from proxy attestation server.  Error received: {:?}.", e);

                    e
                })?;
                let cert_chain = pasr.get_cert_chain();
                let root_cert = cert_chain.get_root_cert();
                let compute_cert = cert_chain.get_enclave_cert();

                (root_cert.to_vec(), compute_cert.to_vec())
            };

            info!("Certificate chain received from proxy attestation server.  Forwarding to runtime manager enclave.");

            send_message(&mut runtime_manager_socket, &RuntimeManagerRequest::Initialize(String::from(policy), vec![compute_cert, root_cert])).map_err(|e| {
                error!("Failed to send certificate chain message to runtime manager enclave.  Error returned: {:?}.", e);

                e
            })?;

            info!("Certificate chain message sent, awaiting response.");

            let received: RuntimeManagerResponse = receive_message(&mut runtime_manager_socket).map_err(|e| {
                error!("Failed to receive response to certificate chain message message from runtime manager enclave.  Error returned: {:?}.", e);

                e
            })?;

                Ok((received, runtime_manager_socket))
            })().map_err(|e| {
                info!("Error in parent: Killing Runtime Manager process...");
                let _ = runtime_manager_process.kill();
                e
            })?;

            info!("Response received.");

            return match received {
                RuntimeManagerResponse::Status(Status::Success) => {
                    info!("Received success message from runtime manager enclave.");

                    Ok(Self {
                        runtime_manager_process,
                        runtime_manager_socket,
                        runtime_enclave_binary_dir,
                    })
                }
                RuntimeManagerResponse::Status(otherwise) => {
                    error!(
                        "Received non-success error code from runtiem manager: {:?}.",
                        otherwise
                    );

                    Err(VeracruzServerError::Status(otherwise))
                }
                otherwise => {
                    error!(
                        "Received unexpected response from runtime manager enclave: {:?}.",
                        otherwise
                    );

                    Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ))
                }
            };
        }

        #[inline]
        fn plaintext_data(&mut self, _data: Vec<u8>) -> VeracruzServerResult<Option<Vec<u8>>> {
            Err(VeracruzServerError::UnimplementedError)
        }

        fn new_tls_session(&mut self) -> VeracruzServerResult<u32> {
            info!("Requesting new TLS session.");

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerRequest::NewTlsSession,
            )?;

            info!("New TLS session message successfully sent.");

            info!("Awaiting response...");

            let message: RuntimeManagerResponse =
                receive_message(&mut self.runtime_manager_socket)?;

            match message {
                RuntimeManagerResponse::TlsSession(session_id) => {
                    info!("Enclave started new TLS session with ID: {}.", session_id);
                    Ok(session_id)
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ))
                }
            }
        }

        fn close_tls_session(&mut self, session_id: u32) -> VeracruzServerResult<()> {
            info!("Requesting close of TLS session with ID: {}.", session_id);

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerRequest::CloseTlsSession(session_id),
            )?;

            info!("Close TLS session message successfully sent.");

            info!("Awaiting response...");

            let message: RuntimeManagerResponse =
                receive_message(&mut self.runtime_manager_socket)?;

            info!("Response received.");

            match message {
                RuntimeManagerResponse::Status(Status::Success) => {
                    info!("TLS session successfully closed.");
                    Ok(())
                }
                RuntimeManagerResponse::Status(status) => {
                    error!("TLS session close request resulted in unexpected status message.  Received: {:?}.", status);
                    Err(VeracruzServerError::Status(status))
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ))
                }
            }
        }

        fn tls_data(
            &mut self,
            session_id: u32,
            input: Vec<u8>,
        ) -> VeracruzServerResult<(bool, Option<Vec<Vec<u8>>>)> {
            info!(
                "Sending TLS data to runtime manager enclave (with session {}).",
                session_id
            );

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerRequest::SendTlsData(session_id, input),
            )?;

            info!("TLS data successfully sent.");

            info!("Awaiting response...");

            let message: RuntimeManagerResponse =
                receive_message(&mut self.runtime_manager_socket)?;

            info!("Response received.");

            match message {
                RuntimeManagerResponse::Status(Status::Success) => {
                    info!("Runtime Manager enclave successfully received TLS data.")
                }
                RuntimeManagerResponse::Status(otherwise) => {
                    error!("Runtime Manager enclave failed to receive TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::Status(otherwise));
                }
                otherwise => {
                    error!("Runtime Manager enclave produced an unexpected response to TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        otherwise,
                    ));
                }
            }

            let mut active = true;
            let mut buffer = Vec::new();

            info!("Reading TLS data...");

            while self.tls_data_needed(session_id)? {
                let (alive_status, received) = self.read_tls_data(session_id)?;

                active = alive_status;
                buffer.push(received);
            }

            info!(
                "Finished reading TLS data (active = {}, received {} bytes).",
                active,
                buffer.len()
            );

            if buffer.is_empty() {
                Ok((active, None))
            } else {
                Ok((active, Some(buffer)))
            }
        }

        /// Kills the Runtime Manager enclave, then closes TCP connection.
        #[inline]
        fn shutdown_isolate(&mut self) -> Result<(), Box<dyn Error>> {
            info!("Shutting down Linux runtime manager enclave.");

            info!("Closing TCP connection...");
            self.runtime_manager_socket.shutdown(Shutdown::Both)?;

            info!("Killing and Runtime Manager process...");
            self.runtime_manager_process.kill()?;

            info!("TCP connection and process killed.");
            Ok(())
        }
    }
}
