//! Linux-specific material for the Runtime Manager enclave
//!
//! NB: note that the attestation flow presented in this
//! module is *completely* insecure and just presented here as a
//! mockup of what a real attestation flow should look like.  See
//! the AWS Nitro Enclave attestation flow for a real example.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::managers::{
    session_manager::{
        close_session, generate_csr, get_data, get_data_needed, init_session_manager,
        load_cert_chain, load_policy, new_session, send_data,
    },
    RuntimeManagerError,
};
use bincode::{deserialize, serialize};
use clap::{App, Arg};
use hex::decode_to_slice;
use io_utils::fd::{receive_buffer, send_buffer};
use log::{error, info, trace};
use psa_attestation::{
    psa_initial_attest_get_token, psa_initial_attest_load_key, psa_initial_attest_remove_key,
};
use ring::digest::{digest, SHA256};
use std::net::TcpListener;
use veracruz_utils::platform::vm::{RuntimeManagerMessage, VMStatus};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Incoming address to listen on.  Note that `0.0.0.0` implies all addresses.
const INCOMING_ADDRESS: &'static str = "0.0.0.0";

/// **TOTALLY INSECURE** root private key to use for Linux PSA attestation.
///
/// NOTE that Linux attestation is "mocked up" and totally insecure.  See the attestation flow for
/// AWS Nitro Enclaves for a secure attestation implementation.  This is merely here for
/// illustrative purposes.
static TOTALLY_INSECURE_ROOT_PRIVATE_KEY: [u8; 32] = [
    0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
    0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x05, 0x76, 0xa1, 0x44,
];

////////////////////////////////////////////////////////////////////////////////
// Initialization.
////////////////////////////////////////////////////////////////////////////////

/// Initializes the runtime manager, bringing up a new session manager instance.
fn initialize() -> RuntimeManagerMessage {
    if let Err(e) = init_session_manager() {
        error!(
            "Failed to initialize session manager.  Error produced: {:?}.",
            e
        );

        return RuntimeManagerMessage::Status(VMStatus::Fail);
    }

    info!("Session manager initialized.");

    RuntimeManagerMessage::Status(VMStatus::Success)
}

////////////////////////////////////////////////////////////////////////////////
// Native attestation (dummy implementation).
////////////////////////////////////////////////////////////////////////////////

/// Performs a dummy implementation of native attestation using the insecure
/// root private keys and computing the runtime manager hash.  If successful, produces a PSA
/// attestation token binding the CSR hash, runtime manager hash, and challenge.
fn native_attestation(
    csr: Vec<u8>,
    challenge: Vec<u8>,
    runtime_manager_hash: &[u8],
) -> Result<Vec<u8>, RuntimeManagerError> {
    let csr_hash = digest(&SHA256, &csr);

    let mut root_key_handle: u32 = 0;

    let ret = unsafe {
        psa_initial_attest_load_key(
            TOTALLY_INSECURE_ROOT_PRIVATE_KEY.as_ptr(),
            TOTALLY_INSECURE_ROOT_PRIVATE_KEY.len() as u64,
            &mut root_key_handle,
        )
    };

    if 0 != ret {
        return Err(RuntimeManagerError::UnsafeCallError(
            "psa_initial_attest_load_key",
            ret as u32,
        ));
    }

    let mut token = Vec::with_capacity(2048);
    let mut token_len: u64 = 0;

    let ret = unsafe {
        psa_initial_attest_get_token(
            runtime_manager_hash.as_ptr(),
            runtime_manager_hash.len() as u64,
            csr_hash.as_ref().as_ptr() as *const u8,
            csr_hash.as_ref().len() as u64,
            std::ptr::null() as *const i8,
            0,
            challenge.as_ptr() as *const u8,
            challenge.len() as u64,
            token.as_mut_ptr() as *mut u8,
            token.capacity() as u64,
            &mut token_len as *mut u64,
        )
    };

    if 0 != ret {
        return Err(RuntimeManagerError::UnsafeCallError(
            "psa_initial_attest_get_token",
            ret as u32,
        ));
    }

    unsafe { token.set_len(token_len as usize) };

    let ret = unsafe { psa_initial_attest_remove_key(root_key_handle) };

    if 0 != ret {
        return Err(RuntimeManagerError::UnsafeCallError(
            "psa_initial_attest_remove_key",
            ret as u32,
        ));
    }

    Ok(token)
}

////////////////////////////////////////////////////////////////////////////////
// Entry point and message dispatcher.
////////////////////////////////////////////////////////////////////////////////

/// Main entry point for Linux: parses command line arguments to find the port
/// number we should be listening on for incoming connections from the Veracruz
/// server.  Parses incoming messages, and acts on them.
pub fn linux_main() -> Result<(), RuntimeManagerError> {
    env_logger::init();

    let matches = App::new("Linux runtime manager enclave")
        .author("The Veracruz Development Team")
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .takes_value(true)
                .required(true)
                .help("Port to listen for new connections on.")
                .value_name("PORT"),
        )
        .arg(
            Arg::with_name("runtime_manager_measurement")
                .short("m")
                .long("measurement")
                .takes_value(true)
                .required(true)
                .help("SHA256 measurement of the Runtime Manager enclave binary.")
                .value_name("MEASUREMENT"),
        )
        .get_matches();

    let port = if let Some(port) = matches.value_of("port") {
        info!("Received {} as port to listen on.", port);
        port
    } else {
        error!("Did not receive any port to listen on.  Exiting...");
        return Err(RuntimeManagerError::CommandLineArguments);
    };

    let measurement = if let Some(measurement) = matches.value_of("runtime_manager_measurement") {
        info!(
            "Received {} as Runtime Manager enclave measurement.",
            measurement
        );
        measurement
    } else {
        error!("Did not receive any expected Runtime Manager enclave measurement.  Exiting...");
        return Err(RuntimeManagerError::CommandLineArguments);
    };

    let mut measurement_bytes = vec![0u8; 32];

    if let Err(err) = decode_to_slice(measurement, &mut measurement_bytes) {
        error!(
            "Failed to decode Runtime Manager measurement ({}).  Error produced: {:?}.",
            measurement, err
        );

        return Err(RuntimeManagerError::CommandLineArguments);
    }

    let address = format!("{}:{}", INCOMING_ADDRESS, port);

    info!("Preparing to listen on {}.", address);

    let listener = TcpListener::bind(&address).map_err(|e| {
        error!("Could not bind TCP listener.  Error produced: {}.", e);

        RuntimeManagerError::IOError(e)
    })?;

    info!("TCP listener created on {}.", address);

    let (mut fd, client_addr) = listener.accept().map_err(|ioerr| {
        error!(
            "Failed to accept any incoming TCP connection.  Error produced: {}.",
            ioerr
        );
        RuntimeManagerError::IOError(ioerr)
    })?;

    // Configure TCP to flush outgoing buffers immediately. This reduces latency
    // when dealing with small packets
    let _ = fd.set_nodelay(true);

    info!("TCP listener connected on {:?}.", client_addr);

    loop {
        info!("Listening for incoming message...");

        let received_buffer: Vec<u8> = receive_buffer(&mut fd).map_err(|err| {
            error!("Failed to receive message.  Error produced: {}.", err);
            RuntimeManagerError::IOError(err)
        })?;

        let received_message: RuntimeManagerMessage =
            deserialize(&received_buffer).map_err(|derr| {
                error!(
                    "Failed to deserialize received message.  Error produced: {}.",
                    derr
                );
                RuntimeManagerError::BincodeError(derr)
            })?;

        info!("Received message.");
        trace!("Received message: {:?}.", received_message);

        let return_message = match received_message {
            RuntimeManagerMessage::Attestation(challenge, _challenge_id) => {
                info!("Initializing enclave.");

                initialize();

                info!(
                    "Generating attestation data from challenge {:?}.",
                    challenge
                );

                let csr = generate_csr().map_err(|e| {
                    error!(
                        "Failed to generate certificate signing request.  Error produced: {:?}.",
                        e
                    );

                    e
                })?;

                let token = native_attestation(csr.clone(), challenge, &measurement_bytes)
                    .map_err(|e| {
                        error!(
                            "Failed to generate native attestation token.  Error produced: {:?}.",
                            e
                        );

                        e
                    })?;

                RuntimeManagerMessage::AttestationData(token, csr)
            }
            RuntimeManagerMessage::Initialize(policy_json, chain) => {
                info!("Loading policy: {}.", policy_json);

                if let Err(e) = load_policy(&policy_json) {
                    error!("Failed to load policy.  Error produced: {:?}.", e);

                    RuntimeManagerMessage::Status(VMStatus::Fail)
                } else {
                    info!("Setting certificate chain.");

                    load_cert_chain(&chain).map_err(|e| {
                        error!("Failed to set certificate chain.  Error produced: {:?}.", e);

                        e
                    })?;

                    RuntimeManagerMessage::Status(VMStatus::Success)
                }
            }
            RuntimeManagerMessage::NewTLSSession => {
                info!("Initiating new TLS session.");

                new_session()
                    .map(|session_id| RuntimeManagerMessage::TLSSession(session_id))
                    .unwrap_or_else(|e| {
                        error!(
                            "Could not initiate new TLS session.  Error produced: {:?}.",
                            e
                        );
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::CloseTLSSession(session_id) => {
                info!("Closing TLS session.");

                close_session(session_id)
                    .map(|_e| RuntimeManagerMessage::Status(VMStatus::Success))
                    .unwrap_or_else(|e| {
                        error!("Failed to close TLS session.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::GetTLSDataNeeded(session_id) => {
                info!("Checking whether TLS data is needed.");

                get_data_needed(session_id)
                    .map(|needed| RuntimeManagerMessage::TLSDataNeeded(needed))
                    .unwrap_or_else(|e|{
                        error!("Failed to check whether further TLS data needed.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::GetTLSData(session_id) => {
                info!("Retrieving TLS data.");

                get_data(session_id)
                    .map(|(active, data)| RuntimeManagerMessage::TLSData(data, active))
                    .unwrap_or_else(|e| {
                        error!("Failed to retrieve TLS data.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            RuntimeManagerMessage::SendTLSData(session_id, tls_data) => {
                info!("Sending TLS data.");

                send_data(session_id, &tls_data)
                    .map(|_| RuntimeManagerMessage::Status(VMStatus::Success))
                    .unwrap_or_else(|e| {
                        error!("Failed to send TLS data.  Error produced: {:?}.", e);
                        RuntimeManagerMessage::Status(VMStatus::Fail)
                    })
            }
            otherwise => {
                error!("Received unknown or unimplemented opcode: {:?}.", otherwise);
                RuntimeManagerMessage::Status(VMStatus::Unimplemented)
            }
        };

        let return_buffer = serialize(&return_message).map_err(|serr| {
            error!(
                "Failed to serialize returned message.  Error produced: {}.",
                serr
            );
            RuntimeManagerError::BincodeError(serr)
        })?;

        info!("Sending message");
        trace!("Sending message: {:?}.", return_message);

        send_buffer(&mut fd, &return_buffer).map_err(|e| {
            error!("Failed to send message.  Error produced: {}.", e);
            RuntimeManagerError::IOError(e)
        })?;
    }
}
