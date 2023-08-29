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

use anyhow::anyhow;
use data_encoding::HEXLOWER;
use io_utils::tcp::{receive_message, send_message};
use lazy_static::lazy_static;
use log::{error, info};
use nix::sys::signal;
use nix::unistd::alarm;
use policy_utils::policy::Policy;
use proxy_attestation_client;
use rand::Rng;
use std::{
    env,
    error::Error,
    fs::{self, File},
    io::Read,
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    process::{Child, Command},
};
use veracruz_server::common::{VeracruzServer, VeracruzServerError};
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};
use veracruz_utils::sha256::sha256;

////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////

lazy_static! {
    /// The Runtime Manager path
    static ref RUNTIME_ENCLAVE_BINARY_PATH: String = {
        match env::var("RUNTIME_ENCLAVE_BINARY_PATH") {
            Ok(val) => val,
            Err(_) => "/work/veracruz/workspaces/linux-runtime/target/debug/linux-runtime-manager".to_string(),
         }
    };
}
/// Delay (in seconds) before terminating this process with SIGALRM if
/// the Runtime Manager has not yet started up.
const RUNTIME_ENCLAVE_STARTUP_TIMEOUT: u32 = 30;
/// IP address for use by Runtime Manager enclave.
const VERACRUZ_SERVER_ADDRESS: &str = "127.0.0.1";
/// Minimum port number for the Runtime Manager enclave.
const RUNTIME_MANAGER_ENCLAVE_PORT_MIN: i32 = 6000;
/// Maximum port number for the Runtime Manager enclave.
const RUNTIME_MANAGER_ENCLAVE_PORT_MAX: i32 = 6999;

/// A struct capturing all the metadata needed to start and communicate with
/// the Linux root enclave.
pub struct VeracruzServerLinux {
    /// A handle to the Runtime Manager enclave process.
    runtime_manager_process: Child,
    /// The socket used to communicate with the Runtime Manager enclave.
    runtime_manager_socket: TcpStream,
}

impl VeracruzServerLinux {
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
    fn new(policy_json: &str) -> Result<Self, VeracruzServerError>
    where
        Self: Sized,
    {
        // TODO: add in dummy measurement and attestation token issuance here
        // which will use fields from the JSON policy file.
        let policy: Policy = Policy::from_json(policy_json).map_err(|e| {
            error!(
                "Failed to parse Veracruz policy file.  Error produced: {:?}.",
                e
            );
            e
        })?;

        println!(
            "Looking at *RUNTIME_ENCLAVE_BINARY_PATH:{:?}",
            *RUNTIME_ENCLAVE_BINARY_PATH
        );
        // make sure our image is executable
        let mut runtime_enclave_binary_permissions =
            fs::metadata(&*RUNTIME_ENCLAVE_BINARY_PATH)?.permissions();
        runtime_enclave_binary_permissions.set_mode(0o500); // readable and executable by user is all we need
        fs::set_permissions(
            &*RUNTIME_ENCLAVE_BINARY_PATH,
            runtime_enclave_binary_permissions,
        )?;

        info!(
            "Computing measurement of runtime manager enclave (using binary {:?})",
            *RUNTIME_ENCLAVE_BINARY_PATH
        );

        let measurement = match File::open(&*RUNTIME_ENCLAVE_BINARY_PATH) {
            Ok(mut file) => {
                let mut buffer = Vec::new();

                if let Err(err) = file.read_to_end(&mut buffer) {
                    error!(
                        "Failed to read file: {:?}.  Error produced: {}.",
                        *RUNTIME_ENCLAVE_BINARY_PATH, err
                    );

                    return Err(VeracruzServerError::IOError(err));
                }

                let digest = sha256(&buffer);
                HEXLOWER.encode(digest.as_ref())
            }
            Err(err) => {
                error!("Failed to open file: {:?}.", *RUNTIME_ENCLAVE_BINARY_PATH);
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
            *RUNTIME_ENCLAVE_BINARY_PATH, port
        );

        let address = format!("{}:{}", VERACRUZ_SERVER_ADDRESS, port);
        let listener = TcpListener::bind(&address).map_err(|e| {
            error!("Could not bind TCP listener: {}", e);
            VeracruzServerError::IOError(e)
        })?;
        info!("TCP listener created on {}.", address);

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
        let mut runtime_manager_process = Command::new(&*RUNTIME_ENCLAVE_BINARY_PATH)
            .arg("--address")
            .arg(format!("{}:{}", VERACRUZ_SERVER_ADDRESS, port))
            .arg("--measurement")
            .arg(measurement)
            .spawn()
            .map_err(|e| {
                error!(
                    "Failed to launch Runtime Manager enclave.  Error produced: {:?}.",
                    e
                );

                VeracruzServerError::IOError(e)
            })?;
        info!("Runtime Manager has been spawned.");

        // Use a closure here so that we can catch any error and
        // terminate the runtime manager.
        let (received, runtime_manager_socket) = (|| {

            // Request SIGALRM after the specified time has elapsed.
            alarm::set(RUNTIME_ENCLAVE_STARTUP_TIMEOUT);

            let (mut runtime_manager_socket, _) = listener.accept().map_err(|ioerr| {
                error!(
                    "Failed to accept any incoming TCP connection.  Error produced: {}.",
                    ioerr
                );
                VeracruzServerError::IOError(ioerr)
            })?;
            info!("Accepted connection from Runtime Manager.");

            // Cancel the alarm.
            alarm::cancel();

            // Configure TCP to flush outgoing buffers immediately. This reduces
            // latency when dealing with small packets
            let _ = runtime_manager_socket.set_nodelay(true);

            info!("Sending proxy attestation 'start' message.");

            let proxy_attestation_server_url = policy.proxy_attestation_server_url();

            let (challenge_id, challenge) = proxy_attestation_client::start_proxy_attestation(
                proxy_attestation_server_url,
            )
                .map_err(|e| {
                    error!(
                        "Failed to start proxy attestation process.  Error received: {:?}.",
                        e
                    );
                    e
                })?;

            // Send a message to the runtime manager
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

            let cert_chain = {
                let cert_chain = proxy_attestation_client::complete_proxy_attestation_linux(proxy_attestation_server_url, &token, &csr, challenge_id)
                    .map_err(|err| {
                        error!("proxy_attestation_client::complete_proxy_attestation_linux failed:{:?}", err);
                        err
                    })?;
                cert_chain
            };

            info!("Certificate chain received from proxy attestation server.  Forwarding to runtime manager enclave.");

            send_message(&mut runtime_manager_socket, &RuntimeManagerRequest::Initialize(String::from(policy_json), cert_chain)).map_err(|e| {
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

    fn send_buffer(&mut self, buffer: &[u8]) -> Result<(), VeracruzServerError> {
        io_utils::fd::send_buffer(&self.runtime_manager_socket, buffer)?;
        return Ok(());
    }

    fn receive_buffer(&mut self) -> Result<Vec<u8>, VeracruzServerError> {
        io_utils::fd::receive_buffer(&self.runtime_manager_socket)
            .map_err(|err| VeracruzServerError::Anyhow(anyhow!(err)))
    }
}
