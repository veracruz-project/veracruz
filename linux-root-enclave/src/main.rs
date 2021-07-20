//! The root enclave (read: application) for Linux
//!
//! Interprets command messages sent over a TCP socket, acts on them, then sends
//! responses back.  Command messages consist of:
//!
//!  - Requests to shutdown the root enclave, which terminates the listening
//!    loop,
//!  - Requests to obtain the hash of the Linux root enclave server,
//!  - Requests for proxy and native attestation tokens,
//!  - A **hack** message which sets the hash of the runtime manager enclave to
//!    a given value for attestation purposes.  This is because the operating
//!    system (Linux in this case) provides no way of reliably measuring a
//!    loaded program.
//!
//! **NOTE**: the attestation flow defined in this file is completely insecure,
//! and can probably never be made really secure.
//!
//! As a result, we've cut a few corners implementing this (e.g. with the
//! pre-generated `LINUX_ROOT_ENCLAVE_PRIVATE_KEY` embedded in the source below)
//! which need fixing if they are to be used in a security-sensitive setting.
//!
//! See the comparable Intel SGX or AWS Nitro flows for a secure and reliable
//! implementation of attestation for Veracruz.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for copyright
//! and licensing information.

use base64::{decode as base64decode, encode as base64encode};
use bincode::{deserialize, serialize, Error as BincodeError};
use curl::{
    easy::{Easy, List},
    Error as CurlError,
};
use env_logger;
use err_derive::Error;
use hex::encode;
use lazy_static::lazy_static;
use log::{error, info};
use net2::{unix::UnixTcpBuilderExt, TcpBuilder};
use nix::Error as NixError;
use psa_attestation::psa_initial_attest_get_token;
use ring::rand::SecureRandom;
use ring::{
    digest::{digest, SHA256},
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use std::{
    collections::HashMap,
    env::current_exe,
    fs::File,
    io::{Error as IOError, Read},
    path::Path,
    process::{Child, Command},
    str::from_utf8,
    sync::{
        atomic::{AtomicI32, AtomicU32, Ordering},
        Mutex,
    },
    thread::sleep,
    time::Duration,
};
use stringreader::StringReader;
use transport_protocol::{
    parse_proxy_attestation_server_response, parse_psa_attestation_init,
    serialize_native_psa_attestation_token, serialize_start_msg,
};
use veracruz_utils::{
    csr::{convert_csr_to_cert, COMPUTE_ENCLAVE_CERT_TEMPLATE},
    platform::linux::{
        receive_buffer, send_buffer, LinuxRootEnclaveMessage, LinuxRootEnclaveResponse,
    },
};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Incoming address to listen on.  Note that "0.0.0.0" means that we listen on
/// all addresses.
const INCOMING_ADDRESS: &'static str = "0.0.0.0";
/// Incoming port to listen on.
const INCOMING_PORT: &'static str = "5021";
/// Socket backlog for incoming connections.
const SOCKET_BACKLOG: i32 = 127;
/// Path to the Runtime Manager binary.
const RUNTIME_MANAGER_ENCLAVE_PATH: &'static str =
    "../runtime-manager/target/x86_64-unknown-linux-gnu/release/runtime_manager_enclave";
/// The attestation protocol to use when communicating with the Proxy Attestation Server.
const PROXY_ATTESTATION_PROTOCOL: &'static str = "PSA";
/// Seconds to wait after spawning an enclave before proceeding.
const ENCLAVE_SPAWN_DELAY: u64 = 2;

lazy_static! {
    /// A private-key randomly generated when the Linux root enclave
    /// initializes.
    static ref DEVICE_PRIVATE_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    /// The ID assigned to this device.
    static ref DEVICE_ID: Mutex<Option<i32>> = Mutex::new(None);
    /// NOTE: this is hardcoded into the root enclave binary, which is
    /// completely insecure.  A better way of doing this would be to generate a
    /// key at initialization time and share this with the proxy attestation
    /// service.  However, this Linux flow is a dummy attestation flow that has
    /// limited value, anyway, given that Linux processes are not secured
    /// against a malicious operating system.  We therefore use this approach
    /// instead, at least for the time being.
    static ref LINUX_ROOT_ENCLAVE_PRIVATE_KEY: Vec<u8> = vec![
        0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
        0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x5, 0x76, 0xa1, 0x44,
    ];
    /// Handles to all of the processes of the enclaves launched by the root
    /// enclave.
    static ref LAUNCHED_ENCLAVES: Mutex<Vec<Child>> = Mutex::new(Vec::new());
    /// A monotonically-increasing counter to keep track of which challenge IDs
    /// were sent to which compute enclaves.
    static ref CHALLENGE_ID: AtomicI32 = AtomicI32::new(0);
    /// Mutex to hold the certificate chain provided by the Proxy Attestation
    /// Service after a successful native attestation.
    static ref CERTIFICATE_CHAIN: Mutex<Option<(Vec<u8>, Vec<u8>)>> = Mutex::new(None);
    /// A hash map for storing challenge values associated with their IDs.
    static ref CHALLENGE_HASHES: Mutex<HashMap<i32, Vec<u8>>> =
        Mutex::new(HashMap::new());
    /// The next port to use to communicate with a newly-launched compute
    /// enclave.
    static ref ENCLAVE_PORT: AtomicU32 = AtomicU32::new(6000);
}

////////////////////////////////////////////////////////////////////////////////
// Errors.
////////////////////////////////////////////////////////////////////////////////

/// Captures all of the different errors that can be produced when trying to
/// listen on, and subsequently process, all of the root enclave messages.
#[derive(Debug, Error)]
enum LinuxRootEnclaveError {
    #[error(display = "PSA attestation process failed.")]
    /// Some aspect of the attestation process failed to complete correctly.
    AttestationError,
    #[error(display = "Base 64 decoding error.")]
    /// There was an error deserializing a message from Base 64 encoding.
    Base64Error,
    #[error(display = "Cryptography key generation process failed.")]
    /// Some aspect of the key generation process failed to complete correctly.
    CryptographyError,
    /// Interaction with the Proxy Attestation Server via Curl failed with
    /// an error.
    #[error(
        display = "Failed to interact with Proxy Attestation Server via Curl.  Error produced: {:?}.",
        _0
    )]
    CurlError(CurlError),
    /// Bincode failed to serialize or deserialize a message or response.
    #[error(
        display = "Failed to serialize or deserialize a message or response.  Error produced: {}.",
        _0
    )]
    BincodeError(BincodeError),
    #[error(
        display = "General IO error when reading or writing files.  Error produced: {}.",
        _0
    )]
    /// There was an error related to the reading or writing of files needed by
    /// the root enclave.
    GeneralIOError(IOError),
    #[error(display = "HTTP non-success error code received.")]
    /// A HTTP session ended in a non-successful state.
    HttpSuccess,
    #[error(display = "An internal invariant failed.")]
    /// An internal invariant failed, i.e. something that was not initialized that
    /// should have been.
    InvariantFailed,
    #[error(display = "A lock on a global object could not be obtained.")]
    /// A lock on a global object could not be obtained.
    LockingError,
    #[error(display = "Socket IO error.  Error produced: {}.", _0)]
    /// There was an error either opening, or working with, sockets.
    SocketError(IOError),
    #[error(display = "Transport Protocol (de)serialization error.")]
    /// There was an error in serializing or deserializing a transport protocol
    /// message.
    TransportProtocolError,
}

////////////////////////////////////////////////////////////////////////////////
// Measurement.
////////////////////////////////////////////////////////////////////////////////

/// Computes a measurement, using SHA-256, of the binary at `path`.  Fails if
/// the binary at the path cannot be read.
fn measure_binary<T>(path: T) -> Result<Vec<u8>, LinuxRootEnclaveError>
where
    T: AsRef<Path>,
{
    let path = path.as_ref();

    info!("Computing measurement of binary: {:?}.", path);

    let mut file = File::open(path).map_err(|e| {
        error!("Failed to open binary {:?}.  Error produced: {}.", path, e);

        LinuxRootEnclaveError::GeneralIOError(e)
    })?;

    let mut buffer = Vec::new();
    let length = file.read_to_end(&mut buffer).map_err(|e| {
        error!(
            "Failed to read contents of binary {:?}.  Error produced: {}.",
            path, e
        );

        LinuxRootEnclaveError::GeneralIOError(e)
    })?;

    info!("Read {:?} bytes from binary.", length);

    let measurement = digest(&SHA256, &buffer).as_ref().to_vec();

    info!("Measurement computed: {}.", encode(&measurement));

    Ok(measurement)
}

/// Computes the measurement of the root enclave binary (i.e. this executable).
fn get_root_enclave_hash() -> Result<Vec<u8>, LinuxRootEnclaveError> {
    info!("Computing root enclave measurement.");

    let path = current_exe().map_err(|e| {
        error!(
            "Failed to obtain the path of the runtime enclave.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::GeneralIOError(e)
    })?;

    measure_binary(path)
}

/// Returns the measurement of the Runtime Manager binary.
#[inline]
fn get_runtime_manager_hash() -> Result<Vec<u8>, LinuxRootEnclaveError> {
    measure_binary(RUNTIME_MANAGER_ENCLAVE_PATH)
}

////////////////////////////////////////////////////////////////////////////////
// Proxy Attestation Service interaction.
////////////////////////////////////////////////////////////////////////////////

/// Sends an encoded `buffer` via HTTP to a server at `url`.  Fails if the
/// Curl session fails for any reason, or if a non-success HTTP code is
/// returned.
fn post_buffer(url: &str, buffer: &str) -> Result<String, LinuxRootEnclaveError> {
    info!("Posting buffer of length {} to {}.", buffer.len(), url);

    let mut curl_request = Easy::new();

    curl_request.url(&url).map_err(|err| {
        error!("Failed to set URL with Curl.  Error produced: {:?}.", err);

        LinuxRootEnclaveError::CurlError(err)
    })?;

    let mut headers = List::new();
    headers
        .append("Content-Type: application/octet-stream")
        .map_err(|err| {
            error!(
                "Failed to append `Content-Type` header.  Error produced: {:?}.",
                err
            );

            LinuxRootEnclaveError::CurlError(err)
        })?;

    curl_request.http_headers(headers).map_err(|err| {
        error!(
            "Failed to set HTTP headers with Curl.  Error produced: {:?}.",
            err
        );

        LinuxRootEnclaveError::CurlError(err)
    })?;
    curl_request.post(true).map_err(|err| {
        error!(
            "Failed to set post field to `true` with Curl.  Error produced: {:?}.",
            err
        );

        LinuxRootEnclaveError::CurlError(err)
    })?;
    curl_request
        .post_field_size(buffer.len() as u64)
        .map_err(|err| {
            error!(
                "Failed to set post field size with Curl.  Error produced: {:?}.",
                err
            );

            LinuxRootEnclaveError::CurlError(err)
        })?;

    let mut transfer = curl_request.transfer();
    let mut buffer_reader = StringReader::new(buffer);

    transfer
        .read_function(|buf| Ok(buffer_reader.read(buf).unwrap_or(0)))
        .map_err(|err| {
            error!(
                "Failed to register read function with Curl.  Error produced: {:?}.",
                err
            );

            LinuxRootEnclaveError::CurlError(err)
        })?;

    let mut received_body = String::new();

    transfer
        .write_function(|buf| {
            received_body.push_str(from_utf8(buf).expect({
                error!("Error converting data {:?} from UTF-8.", buf);

                &format!("Error converting data {:?} from UTF-8.", buf)
            }));

            Ok(buf.len())
        })
        .map_err(|err| {
            error!(
                "Failed to register write function with Curl.  Error produced: {:?}.",
                err
            );

            LinuxRootEnclaveError::CurlError(err)
        })?;

    info!("Received response body: {}.", received_body);

    let mut received_header = String::new();

    transfer
        .header_function(|buf| {
            received_header.push_str(from_utf8(buf).expect({
                error!("Error converting data {:?} from UTF-8.", buf);

                &format!("Error converting data {:?} from UTF-8", buf)
            }));

            true
        })
        .map_err(|err| {
            error!(
                "Failed to register header function with Curl.  Error produced: {:?}.",
                err
            );

            LinuxRootEnclaveError::CurlError(err)
        })?;

    transfer.perform().map_err(|err| {
        error!(
            "Failed to perform data transfer with Curl.  Error produced: {:?}.",
            err
        );

        LinuxRootEnclaveError::CurlError(err)
    })?;

    info!("Received response header: {}.", received_header);

    if !received_header.contains("HTTP/1.1 200 OK\r") {
        return Err(LinuxRootEnclaveError::HttpSuccess);
    }

    info!("Buffer successfully posted.");

    Ok(received_body)
}

/// Sends the "Start" message to the Proxy Attestation Server via HTTP.
/// Returns a device ID and a generated challenge from the Proxy Attestation
/// Service, which is generated in response to the "Start" message, if the
/// message is successfully sent.
fn send_proxy_attestation_server_start(
    proxy_attestation_server_url_base: &str,
    firmware_version: &str,
) -> Result<(i32, Vec<u8>), LinuxRootEnclaveError> {
    info!("Sending Start message to Proxy Attestation Service.");

    let start_msg =
        serialize_start_msg(PROXY_ATTESTATION_PROTOCOL, firmware_version).map_err(|e| {
            error!(
                "Failed to serialize Start message.  Error produced: {:?}.",
                e
            );

            LinuxRootEnclaveError::AttestationError
        })?;

    let encoded_start_msg = base64encode(&start_msg);

    let url = format!("{}/Start", proxy_attestation_server_url_base);

    let response = post_buffer(&url, &encoded_start_msg)?;

    info!("Response received from Proxy Attestation Service.");

    let response_body = base64decode(&response).map_err({
        error!(
            "Failed to deserialize response from Proxy Attestation Service.  Error produced: {:?}.",
            e
        );

        LinuxRootEnclaveError::Base64Error
    })?;

    let response = parse_proxy_attestation_server_response(&response_body).map_err(|e| {
        error!("Failed to parse response to Start message from Proxy Attestation Service.  Error produced: {:?}.", e);

        LinuxRootEnclaveError::TransportProtocolError
    })?;

    info!("Response successfully parsed.");

    if response.has_psa_attestation_init() {
        let (challenge, device_id) =
            parse_psa_attestation_init(response.get_psa_attestation_init()).map_err(|e| {
                error!(
                "Failed to parse PSA attestation initialization message.  Error produced: {:?}.",
                e
            );

                LinuxRootEnclaveError::AttestationError
            })?;

        info!("Device ID and challenge successfully obtained from Proxy Attestation Service.");

        Ok((device_id, challenge))
    } else {
        error!("Unexpected response from Proxy Attestation Service.  Expecting PSA attestation initialization message.");

        Err(LinuxRootEnclaveError::AttestationError)
    }
}

fn post_native_attestation_token(
    proxy_attestation_server_base_url: &str,
    token_buffer: &[u8],
    csr: &[u8],
    device_id: i32,
) -> Result<(Vec<u8>, Vec<u8>), LinuxRootEnclaveError> {
    info!(
        "Sending native attestation token ({} bytes) to Proxy Attestation Service.",
        token_buffer.len()
    );

    let serialized_attestation_token =
        serialize_native_psa_attestation_token(token_buffer, csr, device_id).map_err(|e| {
            error!(
                "Failed to serialize native PSA Attestation Token message.  Error produced: {:?}.",
                e
            );

            LinuxRootEnclaveError::TransportProtocolError
        })?;

    let encoded_serialize_attestion_token = base64encode(&serialized_attestation_token);

    let url = format!(
        "{}/{}/AttestationToken",
        proxy_attestation_server_base_url, PROXY_ATTESTATION_PROTOCOL
    );

    let received_buffer = post_buffer(&url, &encoded_serialize_attestion_token).map_err(|e| {
        error!(
            "Failed to transmit native PSA attestation token.  Error produced: {:?}.",
            e
        );

        e
    })?;

    let received_body = base64decode(&received_buffer).map_err(|e| {
        error!("Failed to Base 64 deserialize response from Proxy Attestation Service.  Error produced: {:?}.", e);

        LinuxRootEnclaveError::Base64Error
    })?;

    let response = parse_proxy_attestation_server_response(&received_body).map_err(|e| {
        error!(
            "Failed to deserialize response from Proxy Attestation Service.  Error produced: {:?}.",
            e
        );

        LinuxRootEnclaveError::TransportProtocolError
    })?;

    if response.has_cert_chain() {
        let certificate_chain = response.get_cert_chain();

        info!("Certificate chain received from Proxy Attestation Service.");

        Ok((
            certificate_chain.get_enclave_cert().to_vec(),
            certificate_chain.get_root_cert().to_vec(),
        ))
    } else {
        error!("Unexpected response from Proxy Attestation Service.");

        Err(LinuxRootEnclaveError::AttestationError)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Responses to message stimuli.
////////////////////////////////////////////////////////////////////////////////

/// Launches a new instance of the Runtime Manager enclave.  Assigns a fresh
/// port number to the enclave and returns it if the enclave is successfully
/// launched.  Returns `Err(err)` with a suitable error if the Runtime Manager
/// enclave cannot be launched, or if the internal database of launched enclaves
/// cannot be locked.
fn launch_new_runtime_manager_enclave() -> Result<u32, LinuxRootEnclaveError> {
    info!("Launching new Runtime Manager enclave.");

    let port = ENCLAVE_PORT.fetch_add(1u32, Ordering::SeqCst);

    info!("Assigned port {} to new enclave.", port);

    let command = Command::new(RUNTIME_MANAGER_ENCLAVE_PATH)
        .arg(format!("--port={}", port))
        .spawn()
        .map_err(|e| {
            error!(
                "Failed to launch Runtime Manager enclave ({}).  Error produced: {}.",
                RUNTIME_MANAGER_ENCLAVE_PATH, e
            );

            LinuxRootEnclaveError::GeneralIOError(e)
        })?;

    info!(
        "New Runtime Manager enclave launched.  Sleeping {} seconds...",
        ENCLAVE_SPAWN_DELAY
    );

    sleep(Duration::from_secs(ENCLAVE_SPAWN_DELAY));

    info!("Registering new enclave.");

    let mut children = LAUNCHED_ENCLAVES.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on LAUNCHED_ENCLAVES.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::LockingError
    })?;

    children.push(command);

    Ok(port)
}

/// Kills all of the enclaves that the Linux root enclave has spawned.  If any
/// process cannot be killed then this is logged on the error logger but no
/// further error is produced as we are in the process of exiting when this
/// function is called, anyway.
fn kill_all_enclaves() -> Result<(), LinuxRootEnclaveError> {
    info!("Killing all launched Runtime Manager enclaves.");

    let mut children = LAUNCHED_ENCLAVES.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on LAUNCHED_ENCLAVES.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::LockingError
    })?;

    for child in children.iter_mut() {
        info!("Killing process {}.", child.id());

        let _result = child.kill().map_err(|_e| {
            error!("Failed to kill process {}.", child.id());
        });
    }

    Ok(())
}

/// Returns the version of the trusted runtime's software stack.  Note that on
/// Linux this is mocked up, as the attestation process is completely insecure.
#[inline]
fn get_firmware_version() -> String {
    String::from(env!("CARGO_PKG_VERSION"))
}

/// Produces a fresh 16-byte challenge value, indexed by a new challenge ID, and
/// stashes them in the `CHALLENGE_ID` table before returning them.
fn start_proxy_attestation() -> Result<(Vec<u8>, i32), LinuxRootEnclaveError> {
    let challenge_id = CHALLENGE_ID.fetch_add(1, Ordering::SeqCst);

    info!("Fresh challenge ID generated: {}. ", challenge_id);

    let mut buffer = Vec::with_capacity(16);
    let rng = SystemRandom::new();

    rng.fill(&mut buffer).map_err(|_e| {
        error!("Failed to produced 16 bytes of random data for challenge.");

        LinuxRootEnclaveError::CryptographyError
    })?;

    let mut challenge_hash_lock = CHALLENGE_HASHES.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on CHALLENGE_HASHES.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::LockingError
    })?;

    challenge_hash_lock.insert(challenge_id.clone(), buffer.clone());

    info!("Fresh challenge and challenge ID generated.");

    Ok((buffer, challenge_id))
}

/// Caches the root enclave certificate and the root CA certificate for use
/// later in the attestation process.
fn install_certificate_chain(
    root_enclave_certificate: Vec<u8>,
    root_certificate: Vec<u8>,
) -> Result<(), LinuxRootEnclaveError> {
    let mut certificate_chain_lock = CERTIFICATE_CHAIN.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on CERTIFICATE_CHAIN.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::LockingError
    })?;

    *certificate_chain_lock = Some((root_enclave_certificate, root_certificate));

    info!("Certificate chain installed.");

    Ok(())
}

/// Computes a native PSA attestation token from a Certificate Signing Request and
/// registers this with the Proxy Attestation Service.  Registers the resulting
/// certificates returned from the Proxy Attestation Service.
fn native_attestation(
    proxy_attestation_server_base_url: &str,
    csr: Vec<u8>,
) -> Result<(), LinuxRootEnclaveError> {
    /* 1. Get the firmware version. */

    let firmware_version = get_firmware_version()?;

    /* 2. Send the Start message to the Proxy Attestation Service to obtain a device ID and
     *    challenge.
     */

    info!("Initializing Proxy Attestation Service.");

    let (device_id, challenge) =
        send_proxy_attestation_server_start(proxy_attestation_server_base_url, &firmware_version)?;

    /* 2. Save the Device ID. */

    let mut device_id_lock = DEVICE_ID.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on DEVICE_ID.  Error produced: {}.",
            e
        );
        LinuxRootEnclaveError::LockingError
    })?;

    *device_id_lock = Some(device_id.clone());

    info!("Device ID {} saved.", device_id);

    let csr_hash = digest(&SHA256, &csr).as_ref().to_vec();

    info!("CSR hash computed: {:?}.", csr_hash);

    let root_enclave_measurement = get_root_enclave_hash()?;

    info!(
        "Root enclave measurement computed: {:?}.",
        root_enclave_measurement
    );

    let mut token_buffer = Vec::with_capacity(1024);
    let mut token_size = 0u64;

    if 0 != unsafe {
        psa_initial_attest_get_token(
            root_enclave_measurement.as_ptr() as *const u8,
            root_enclave_measurement.len() as u64,
            csr_hash.as_ptr() as *const u8,
            csr_hash.len() as u64,
            std::ptr::null() as *const i8,
            0,
            challenge.as_ptr() as *const u8,
            challenge.len() as u64,
            token_buffer.as_mut_ptr() as *mut u8,
            token_buffer.capacity() as u64,
            &mut token_size as *mut u64,
        )
    } {
        error!("Failed to produce native PSA attestation token.");
        return Err(LinuxRootEnclaveError::CryptographyError);
    }

    unsafe {
        token_buffer.set_len(token_size as usize);
    }

    info!("Native PSA attestation token successfully produced.");

    info!("Sending native attesation token to Proxy Attestation Service.");

    let (root_enclave_certificate, ca_certificate) =
        post_native_attestation_token(proxy_attestation_server_base_url, &token_buffer, device_id)?;

    info!("Root Enclave Certificate and CA Certificate received from Proxy Attestation Service.");

    let _result = install_certificate_chain(root_enclave_certificate, ca_certificate)?;

    info!("Certificates successfully installed.");

    Ok(())
}

/// Computes a proxy attestation certificate chain from a Certificate Signing
/// Request, `csr`, and a challenge index, `challenge_id`.
fn get_proxy_attestation_certificate_chain(
    csr: Vec<u8>,
    challenge_id: i32,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), LinuxRootEnclaveError> {
    let mut challenge_hashes_lock = CHALLENGE_HASHES.lock().map_err(|e| {
        error!("Failed to lock CHALLENGE_HASHES.  Error produced: {}.", e);

        LinuxRootEnclaveError::LockingError
    })?;

    let _challenge = challenge_hashes_lock.remove(&challenge_id).ok_or_else(|| {
        error!("Unknown challenge ID: {}.", challenge_id);

        LinuxRootEnclaveError::AttestationError
    })?;

    info!("Challenge ID {} found.", challenge_id);

    let runtime_manager_hash = get_runtime_manager_hash()?;

    info!("Runtime Manager hash computed: {:?}.", runtime_manager_hash);

    let device_private_key_lock = DEVICE_PRIVATE_KEY.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on DEVICE_PRIVATE_KEY.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::LockingError
    })?;

    let device_private_key = match &*device_private_key_lock {
        Some(k) => k.clone(),
        None => {
            error!("Device private key is not initialized.");
            return Err(LinuxRootEnclaveError::InvariantFailed);
        }
    };

    let private_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &device_private_key).map_err(
            |e| {
                error!(
                    "Failed to obtain private key from PKCS8 data.  Error produced: {}.",
                    e
                );

                LinuxRootEnclaveError::CryptographyError
            },
        )?;

    let runtime_manager_certificate = convert_csr_to_cert(&csr, &COMPUTE_ENCLAVE_CERT_TEMPLATE, &runtime_manager_hash, &private_key).map_err(|e| {
        error!("Failed to convert Certificate Signing Request (CSR) into certificate.  Error produced: {:?}.", e);

        LinuxRootEnclaveError::CryptographyError
    })?;

    info!("Runtime Manager certificate generated.");

    let certificate_chain_lock = CERTIFICATE_CHAIN.lock().map_err(|e| {
        error!(
            "Failed to obtain lock on CERTIFICATE_CHAIN.  Error produced: {}.",
            e
        );

        LinuxRootEnclaveError::LockingError
    })?;

    let (root_enclave_certificate, root_certificate) = match &*certificate_chain_lock {
        Some((root_enclave_certificate, root_certificate)) => {
            (root_enclave_certificate.clone(), root_certificate.clone())
        }
        None => {
            error!("Root Enclave and Root certificates not stored.");

            return Err(LinuxRootEnclaveError::InvariantFailed);
        }
    };

    info!("Obtained Root Enclave certificate and Root certificate.");

    Ok((
        runtime_manager_certificate,
        root_enclave_certificate,
        root_certificate,
    ))
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

/// Generates a private key for the root enclave to use as part of the
/// attestation process.
fn generate_private_key() -> Result<(), LinuxRootEnclaveError> {
    info!("Generating private key.");

    let rng = SystemRandom::new();

    let pkcs8_bytes =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(|err| {
            error!("Failed to generate PKCS-8 key.  Error produced: {:?}.", err);
            LinuxRootEnclaveError::CryptographyError
        })?;

    let mut private_key_lock = DEVICE_PRIVATE_KEY.lock().map_err(|_e| {
        error!("Failed to obtain lock on DEVICE_PRIVATE_KEY.");
        LinuxRootEnclaveError::LockingError
    })?;

    *private_key_lock = Some(pkcs8_bytes.as_ref().to_vec());

    Ok(())
}

/// Entry point for the root enclave.  This sets up a TCP listener and processes
/// messages, deserializing them using Bincode.  Can fail for a variety of
/// reasons, all of which are captured in the `LinuxRootEnclaveError` type.
fn entry_point() -> Result<(), LinuxRootEnclaveError> {
    info!("Linux root enclave initializing.");

    generate_private_key()?;

    let listen_on = format!("{}:{}", INCOMING_ADDRESS, INCOMING_PORT);

    info!("Starting listening on {}.", listen_on);

    let listener = TcpBuilder::new_v4()
        .map_err(|e| {
            error!("Failed to create new TCP builder.  Error produed: {}.", e);
            LinuxRootEnclaveError::GeneralIOError(e)
        })?
        .reuse_address(true)
        .map_err(|e| {
            error!(
                "Failed to set Reuse Address option on socket.  Error produced: {}.",
                e
            );
            LinuxRootEnclaveError::SocketError(e)
        })?
        .reuse_port(true)
        .map_err(|e| {
            error!(
                "Failed to set Reuse Port option on socket.  Error produced: {}.",
                e
            );
            LinuxRootEnclaveError::SocketError(e)
        })?
        .bind(&listen_on)
        .map_err(|e| {
            error!(
                "Failed to bind socket on {}.  Error produced: {}.",
                listen_on, e
            );
            LinuxRootEnclaveError::SocketError(e)
        })?
        .listen(SOCKET_BACKLOG)
        .map_err(|e| {
            error!("Failed to listen on {}.  Error produced: {}.", listen_on, e);
            LinuxRootEnclaveError::SocketError(e)
        })?;

    info!("Started listening on {}.", listen_on);

    let (mut fd, client_addr) = listener.accept().map_err(|ioerr| {
        error!(
            "Failed to accept any incoming TCP connection.  Error produced: {}.",
            ioerr
        );
        LinuxRootEnclaveError::SocketError(ioerr)
    })?;

    info!("TCP listener connected on {:?}.", client_addr);

    /* Set to `true` when a request to shutdown is received, breaking the
      message processing loop, below.
    */
    let mut shutdown = false;

    while !shutdown {
        let received_buffer: Vec<u8> = receive_buffer(&mut fd).map_err(|e| {
            error!("Failed to receive message.  Error produced: {}.", e);
            LinuxRootEnclaveError::SocketError(e)
        })?;

        let received_message = deserialize(&received_buffer).map_err(|e| {
            error!(
                "Failed to deserialize received message.  Error produced: {}.",
                e
            );
            LinuxRootEnclaveError::BincodeError(e)
        })?;

        info!("Received message: {:?}.", received_message);

        let response = match received_message {
            LinuxRootEnclaveMessage::SpawnNewApplicationEnclave => {
                info!("Spawning new application enclave.");

                Ok(LinuxRootEnclaveResponse::EnclaveSpawned(
                    launch_new_runtime_manager_enclave()?,
                ))
            }
            LinuxRootEnclaveMessage::GetFirmwareVersion => {
                info!("Computing firmware version.");

                Ok(LinuxRootEnclaveResponse::FirmwareVersion(
                    get_firmware_version(),
                ))
            }
            LinuxRootEnclaveMessage::Shutdown => {
                info!("Shutting down the Linux root enclave.");

                shutdown = true;
                kill_all_enclaves()?;

                Ok(LinuxRootEnclaveResponse::ShuttingDown)
            }
            LinuxRootEnclaveMessage::GetNativeAttestation(csr) => {
                info!("Computing a native attestation token.");

                let _result = native_attestation(proxy_attestation_server_base_url, csr)?;

                Ok(LinuxRootEnclaveResponse::NativeAttestationTokenRegistered)
            }
            LinuxRootEnclaveMessage::GetProxyAttestation(csr, challenge_id) => {
                info!("Computing a proxy attestation certificate chain.");

                let (runtime_manager_certificate, root_enclave_certificate, root_certificate) =
                    get_proxy_attestation_certificate_chain(csr, challenge_id)?;

                Ok(LinuxRootEnclaveResponse::CertificateChain(
                    runtime_manager_certificate,
                    root_enclave_certificate,
                    root_certificate,
                ))
            }
            LinuxRootEnclaveMessage::StartProxyAttestation => {
                info!("Generating challenge value and fresh challenge ID.");

                let (challenge, challenge_id) = start_proxy_attestation()?;

                Ok(LinuxRootEnclaveResponse::ChallengeGenerated(
                    challenge,
                    challenge_id,
                ))
            }
        }?;

        info!("Producing response: {:?}.", response);

        let response_buffer = serialize(&response).map_err(|e| {
            error!(
                "Failed to serialize response message.  Error produced: {}.",
                e
            );
            LinuxRootEnclaveError::BincodeError(e)
        })?;

        info!("Sending message with length: {}.", response_buffer.len());

        send_buffer(&mut fd, &response_buffer).map_err(|e| {
            error!("Failed to send response.  Error produced: {}.", e);
            LinuxRootEnclaveError::SocketError(e)
        })?;
    }

    Ok(())
}

/// Main entry point for the program.  Calls `entry_point` and pretty-prints
/// any error that was produced.  Initializes the logging service.
fn main() {
    env_logger::init();

    let _ignore = entry_point().map_err(|e| {
        eprintln!(
            "Linux root enclave runtime failure.  Error produced: {:?}.",
            e
        )
    });
}
