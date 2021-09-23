//! Linux-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "linux")]
pub mod veracruz_server_linux {

    use log::{error, info};

    use std::{
        env,
        net::{Shutdown, TcpStream},
        path::PathBuf,
        process::{Child, Command},
        thread::sleep,
        time::Duration,
    };

    use crate::{veracruz_server::VeracruzServer, VeracruzServerError};
    use io_utils::tcp::{receive_message, send_message};
    use policy_utils::policy::Policy;
    use veracruz_utils::platform::{
        linux::{LinuxRootEnclaveMessage, LinuxRootEnclaveResponse},
        vm::{RuntimeManagerMessage, VMStatus},
    };

    ////////////////////////////////////////////////////////////////////////////
    // Constants.
    ////////////////////////////////////////////////////////////////////////////

    /// Path to the pre-built Linux root enclave.
    const LINUX_ROOT_ENCLAVE_PATH: &'static str =
        "../linux-root-enclave/target/release/linux-root-enclave";
    /// Port to communicate with the Linux root enclave on.
    const LINUX_ROOT_ENCLAVE_PORT: &'static str = "5021";
    /// IP address to use when communicating with the Linux root enclave.
    const LINUX_ROOT_ENCLAVE_ADDRESS: &'static str = "127.0.0.1";
    /// IP address to use when communicating with the Runtime Manager enclave.
    const RUNTIME_MANAGER_ENCLAVE_ADDRESS: &'static str = "127.0.0.1";
    /// Delay (in seconds) to use when spawning the Linux root enclave to
    /// ensure that everything is started before proceeding with communication
    /// between the server and enclave.
    const LINUX_ROOT_ENCLAVE_SPAWN_DELAY_SECONDS: u64 = 2;

    /// A struct capturing all the metadata needed to start and communicate with
    /// the Linux root enclave.
    pub struct VeracruzServerLinux {
        /// A handle to the Linux root enclave's process.
        linux_root_process: Child,
        /// The socket used to communicate with the Runtime Manager enclave.
        runtime_manager_socket: TcpStream,
        /// The socket used to communicate with the Linux Root enclave.
        linux_root_socket: TcpStream,
    }

    impl VeracruzServerLinux {
        /// Tears down the Linux Root enclave, and all spawned Runtime Manager enclaves creates
        /// by it.  Then closes TCP connections and kills the Linux Root enclave process.  Tries
        /// to be as liberal in ignoring erroneous conditions as possible in order to kill as
        /// many things as we can.
        fn teardown(&mut self) -> Result<bool, VeracruzServerError> {
            info!("Tearing down Linux Root enclave, and all Runtime Manager enclaves spawned.");

            info!("Sending shutdown message.");

            send_message(
                &mut self.linux_root_socket,
                &LinuxRootEnclaveMessage::Shutdown,
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Shutdown message successfully sent.");

            info!("Awaiting response...");

            let response: LinuxRootEnclaveResponse = receive_message(&mut self.linux_root_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match response {
                LinuxRootEnclaveResponse::ShuttingDown => {
                    info!("Linux Root enclave and Runtime Manager enclaves killed.");
                    info!("Closing TCP connections.");

                    let _result = self.runtime_manager_socket.shutdown(Shutdown::Both);
                    let _result = self.linux_root_socket.shutdown(Shutdown::Both);
                    let _result = self.linux_root_process.kill();

                    info!("Connections and processes killed.");

                    Ok(true)
                }
                otherwise => {
                    error!(
                        "Received unexpected response from Linux Root enclave: {:?}.",
                        otherwise
                    );

                    info!("Closing TCP connections anyway...");

                    let _result = self.runtime_manager_socket.shutdown(Shutdown::Both);
                    let _result = self.linux_root_socket.shutdown(Shutdown::Both);
                    let _result = self.linux_root_process.kill();

                    info!("Connections and processes killed.");

                    Ok(true)
                }
            }
        }

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
        pub fn tls_data_needed(&mut self, session_id: u32) -> Result<bool, VeracruzServerError> {
            info!("Checking whether TLS data can be read from Runtime Manager enclave (with session: {}).", session_id);

            info!("Sending TLS data check message.");

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::GetTLSDataNeeded(session_id),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("TLS data check message successfully sent.");

            info!("Awaiting response...");

            let received: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match received {
                RuntimeManagerMessage::TLSDataNeeded(response) => {
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

                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
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
        pub fn read_tls_data(
            &mut self,
            session_id: u32,
        ) -> Result<(bool, Vec<u8>), VeracruzServerError> {
            info!(
                "Reading TLS data from Runtime Manager enclave (with session: {}).",
                session_id
            );

            info!("Sending get TLS data message.");

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::GetTLSData(session_id),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Get TLS data message successfully sent.");

            info!("Awaiting response...");

            let received: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match received {
                RuntimeManagerMessage::TLSData(buffer, alive) => {
                    info!("{} bytes of TLS data received from Runtime Manager enclave (alive status: {}).", buffer.len(), alive);

                    Ok((alive, buffer))
                }
                otherwise => {
                    error!("Unexpected reply received back from Runtime Manager enclave.  Recevied: {:?}.", otherwise);

                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
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
            info!("Dropping VeracruzServerLinux object, shutting down enclaves...");
            if let Err(error) = self.teardown() {
                error!(
                    "Failed to forcibly kill Runtime Manager and Linux Root enclave process.  Error produced: {:?}.",
                    error
                );
            }
            info!("VeracruzServerLinux object killed.");
        }
    }

    impl VeracruzServer for VeracruzServerLinux {
        /// Creates a new instance of the `VeracruzServerLinux` type.  To do
        /// this, we:
        ///
        /// 1. Spawn the Linux Root enclave,
        /// 2. Establish a socket connection between us and the Linux Root enclave,
        /// 3. Ask the Linux Root enclave to spawn a new Runtime Manager enclave,
        /// 4. Establish a socket connection to the Runtime Manager enclave on
        ///    the port assigned to us by the Linux Root enclave,
        /// 4. Send initializing messages to both enclaves.
        /// 5. Start the proxy attestation process, getting the certificate
        ///    chain from the Linux Root Enclave (which handles this process on
        ///    Linux).
        /// 6. Register the resulting certificate chain with the Runtime Manager
        ///    enclave, in preparation for TLS connections.
        ///
        /// Note that this process can fail for a number of reasons, e.g. the
        /// enclaves may not be spawnable, socket connections can fail, the
        /// initialization processes of the two enclaves may fail, and so on.
        /// In those cases, an explicit error is returned.  Otherwise, we return
        /// `Ok(vsl)`.
        fn new(policy: &str) -> Result<Self, VeracruzServerError>
        where
            Self: Sized,
        {
            info!("Creating new Veracruz Server instance for Linux.");

            // TODO: add in dummy measurement and attestation token issuance here
            // which will use fields from the JSON policy file.
            let policy_json = Policy::from_json(policy).map_err(|e| {
                error!(
                    "Failed to parse Veracruz policy file.  Error produced: {:?}.",
                    e
                );

                VeracruzServerError::VeracruzUtilError(e)
            })?;

            info!("Successfully parsed JSON policy file.");

            let proxy_attestation_server_url = policy_json.proxy_attestation_server_url();

            let linux_root_enclave_path = PathBuf::from(env::var("LINUX_ROOT_ENCLAVE_PATH").
                unwrap_or(LINUX_ROOT_ENCLAVE_PATH.to_string()));
            info!(
                "Launching Linux Root enclave: {} with proxy attestation server URL: {}.",
                linux_root_enclave_path.to_string_lossy(), proxy_attestation_server_url
            );

            let mut linux_root_process = Command::new(linux_root_enclave_path)
                .arg("--proxy-attestation-server")
                .arg(proxy_attestation_server_url)
                .spawn()
                .map_err(|e| {
                    error!(
                        "Failed to launch Linux Root enclave.  Error produced: {:?}.",
                        e
                    );

                    VeracruzServerError::IOError(e)
                })?;

            info!(
                "Linux Root enclave spawned.  Waiting {:?} seconds...",
                LINUX_ROOT_ENCLAVE_SPAWN_DELAY_SECONDS
            );

            sleep(Duration::from_secs(LINUX_ROOT_ENCLAVE_SPAWN_DELAY_SECONDS));

            let linux_root_enclave_address =
                format!("{}:{}", LINUX_ROOT_ENCLAVE_ADDRESS, LINUX_ROOT_ENCLAVE_PORT);

            info!(
                "Connecting to Linux Root enclave on {}.",
                linux_root_enclave_address
            );

            let mut linux_root_socket =
                TcpStream::connect(linux_root_enclave_address).map_err(|error| {
                    error!(
                        "Failed to connect to Linux Root enclave.  Error produced: {:?}.",
                        error
                    );
                    error!("Killing Linux Root enclave.");

                    // NB: we're in the process of failing here anyway, so we eat any error returned
                    // from this subprocess kill command.
                    let _result = linux_root_process.kill();

                    error
                })?;

            info!(
                "Now connected to Linux Root enclave on: {:?}.",
                linux_root_socket.peer_addr()
            );

            info!("Requesting spawning of new Runtime Enclave.");

            send_message(
                &mut linux_root_socket,
                &LinuxRootEnclaveMessage::SpawnNewApplicationEnclave,
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Spawn request sent.");

            info!("Awaiting response...");

            let response: LinuxRootEnclaveResponse = receive_message(&mut linux_root_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            let runtime_manager_port =
                if let LinuxRootEnclaveResponse::EnclaveSpawned(port) = response {
                    info!("Runtime Manager enclave assigned port: {}.", port);
                    port
                } else {
                    error!(
                        "Unexpected response received from Linux Root enclave.  Received: {:?}.",
                        response
                    );

                    return Err(VeracruzServerError::LinuxRootEnclaveUnexpectedResponse(
                        response,
                    ));
                };

            info!("Requesting proxy attestation start.");

            send_message(
                &mut linux_root_socket,
                &LinuxRootEnclaveMessage::StartProxyAttestation,
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Proxy attestation start message successfully sent.");

            info!("Awaiting response...");

            let response: LinuxRootEnclaveResponse = receive_message(&mut linux_root_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            let (challenge, challenge_id) = match response {
                LinuxRootEnclaveResponse::ChallengeGenerated(challenge, challenge_id) => {
                    (challenge, challenge_id)
                }
                otherwise => {
                    error!(
                        "Unexpected response received from Linux Root enclave.  Received: {:?}.",
                        otherwise
                    );

                    return Err(VeracruzServerError::LinuxRootEnclaveUnexpectedResponse(
                        otherwise,
                    ));
                }
            };

            let runtime_manager_address = format!(
                "{}:{}",
                RUNTIME_MANAGER_ENCLAVE_ADDRESS, runtime_manager_port
            );

            info!(
                "Establishing connection with new Runtime Manager enclave on address: {}.",
                runtime_manager_address
            );

            let mut runtime_manager_socket = TcpStream::connect(&runtime_manager_address).map_err(|e| {
                error!("Failed to connect to Runtime Manager enclave at address {}.  Error produced: {}.", runtime_manager_address, e);

                VeracruzServerError::IOError(e)
            })?;

            info!(
                "Connected to Runtime Manager enclave at address {}.",
                runtime_manager_address
            );

            info!("Sending Initialize message.");

            send_message(
                &mut runtime_manager_socket,
                &RuntimeManagerMessage::Initialize(policy.to_string(), challenge, challenge_id),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Initialize message successfully sent.");

            info!("Awaiting response...");

            let status: RuntimeManagerMessage = receive_message(&mut runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match status {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("Enclaves successfully initialized.");
                }
                RuntimeManagerMessage::Status(status) => {
                    error!("Enclave sent status {:?}.", status);

                    return Err(VeracruzServerError::VMStatus(status));
                }
                otherwise => {
                    error!("Enclave sent unexpected message: {:?}.", otherwise);

                    return Err(VeracruzServerError::RuntimeManagerMessageStatus(otherwise));
                }
            };

            info!("Requesting certificate signing request (CSR).");

            send_message(&mut runtime_manager_socket, &RuntimeManagerMessage::GetCSR)
                .map_err(VeracruzServerError::SocketError)?;

            info!("CSR request successfully sent.");

            info!("Awaiting response...");

            let csr_response: RuntimeManagerMessage = receive_message(&mut runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            let csr = match csr_response {
                RuntimeManagerMessage::GeneratedCSR(csr) => {
                    info!("CSR received ({} bytes).", csr.len());

                    csr.clone()
                }
                otherwise => {
                    error!(
                        "Received unexpected reponse from Linux runtime enclave: {:?}.",
                        otherwise
                    );

                    return Err(VeracruzServerError::RuntimeManagerMessageStatus(otherwise));
                }
            };

            info!("Requesting native attestation token.");

            send_message(
                &mut linux_root_socket,
                &LinuxRootEnclaveMessage::GetNativeAttestation,
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Get native attestation message successfully sent.");

            info!("Awaiting response...");

            let native_attestation_response: LinuxRootEnclaveResponse =
                receive_message(&mut linux_root_socket)
                    .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match native_attestation_response {
                LinuxRootEnclaveResponse::NativeAttestationTokenRegistered => {
                    info!("Native Attestation Token registered.")
                }
                otherwise => {
                    error!(
                        "Unexpected response from Linux Root Enclave.  Received: {:?}.",
                        otherwise
                    );

                    return Err(VeracruzServerError::LinuxRootEnclaveUnexpectedResponse(
                        otherwise,
                    ));
                }
            };

            info!("Requesting certificate chain.");

            send_message(
                &mut linux_root_socket,
                &LinuxRootEnclaveMessage::GetProxyAttestation(csr, challenge_id),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Certificate chain request successfully sent.");

            info!("Awaiting response...");

            let response: LinuxRootEnclaveResponse = receive_message(&mut linux_root_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            let certificate_chain = match response {
                LinuxRootEnclaveResponse::CertificateChain(
                    compute_enclave_certificate,
                    root_enclave_certificate,
                    root_certificate,
                ) => {
                    info!("Certificate chain received.");

                    vec![
                        compute_enclave_certificate,
                        root_enclave_certificate,
                        root_certificate,
                    ]
                }
                otherwise => {
                    error!(
                        "Unexpected response received from Linux Root enclave.  Received: {:?}.",
                        otherwise
                    );

                    return Err(VeracruzServerError::LinuxRootEnclaveUnexpectedResponse(
                        otherwise,
                    ));
                }
            };

            info!("Registering server certificate chain with Linux Runtime Manager enclave.");

            send_message(
                &mut runtime_manager_socket,
                &RuntimeManagerMessage::SetCertificateChain(certificate_chain),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Server certificate chain message successfully sent.");

            info!("Awaiting response...");

            let response: RuntimeManagerMessage = receive_message(&mut runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            return match response {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("Certificate chain successfully installed.");

                    Ok(VeracruzServerLinux {
                        linux_root_process,
                        linux_root_socket,
                        runtime_manager_socket,
                    })
                }
                RuntimeManagerMessage::Status(otherwise) => {
                    error!("Enclave sent status {:?}.", otherwise);

                    Err(VeracruzServerError::VMStatus(otherwise))
                }
                otherwise => {
                    error!("Enclave sent unexpected message: {:?}.", otherwise);

                    Err(VeracruzServerError::RuntimeManagerMessageStatus(otherwise))
                }
            };
        }

        #[inline]
        fn plaintext_data(
            &mut self,
            _data: Vec<u8>,
        ) -> Result<Option<Vec<u8>>, VeracruzServerError> {
            return Err(VeracruzServerError::UnimplementedError);
        }

        fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError> {
            info!("Requesting new TLS session.");

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::NewTLSSession,
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("New TLS session message successfully sent.");

            info!("Awaiting response...");

            let message: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            match message {
                RuntimeManagerMessage::TLSSession(session_id) => {
                    info!("Enclave started new TLS session with ID: {}.", session_id);
                    Ok(session_id)
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }

        fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
            info!("Requesting close of TLS session with ID: {}.", session_id);

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::CloseTLSSession(session_id),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("Close TLS session message successfully sent.");

            info!("Awaiting response...");

            let message: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match message {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("TLS session successfully closed.");
                    Ok(())
                }
                RuntimeManagerMessage::Status(status) => {
                    error!("TLS session close request resulted in unexpected status message.  Received: {:?}.", status);
                    Err(VeracruzServerError::VMStatus(status))
                }
                otherwise => {
                    error!(
                        "Unexpected response returned from enclave.  Received: {:?}.",
                        otherwise
                    );
                    Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise))
                }
            }
        }

        fn tls_data(
            &mut self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            info!(
                "Sending TLS data to runtime manager enclave (with session {}).",
                session_id
            );

            send_message(
                &mut self.runtime_manager_socket,
                &RuntimeManagerMessage::SendTLSData(session_id, input),
            )
            .map_err(VeracruzServerError::SocketError)?;

            info!("TLS data successfully sent.");

            info!("Awaiting response...");

            let message: RuntimeManagerMessage = receive_message(&mut self.runtime_manager_socket)
                .map_err(VeracruzServerError::SocketError)?;

            info!("Response received.");

            match message {
                RuntimeManagerMessage::Status(VMStatus::Success) => {
                    info!("Runtime Manager enclave successfully received TLS data.")
                }
                RuntimeManagerMessage::Status(otherwise) => {
                    error!("Runtime Manager enclave failed to receive TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::VMStatus(otherwise));
                }
                otherwise => {
                    error!("Runtime Manager enclave produced an unexpected response to TLS data.  Response received: {:?}.", otherwise);
                    return Err(VeracruzServerError::InvalidRuntimeManagerMessage(otherwise));
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

        /// Kills the Linux Root enclave, all spawned Runtime Manager enclaves, and all open
        /// TCP connections and processes that we have a handle to.
        #[inline]
        fn close(&mut self) -> Result<bool, VeracruzServerError> {
            info!("Closing...");
            self.teardown()
        }
    }
}
