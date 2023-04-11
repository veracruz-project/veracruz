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
        close_session, generate_csr, get_data, init_session_manager, load_cert_chain, load_policy,
        new_session, send_data,
    },
    RuntimeManagerError,
};
use anyhow::{anyhow, Result};
use bincode::{deserialize, serialize};
use clap::{App, Arg};
use hex::decode_to_slice;
use io_utils::fd::{receive_buffer, send_buffer};
use log::{error, info};
use nix::libc::c_char;
use psa_attestation::{
    psa_initial_attest_get_token, psa_initial_attest_load_key, psa_initial_attest_remove_key,
};
use std::net::TcpStream;
use veracruz_utils::{
    runtime_manager_message::{RuntimeManagerRequest, RuntimeManagerResponse, Status},
    sha256::sha256,
};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// **TOTALLY INSECURE** root private key to use for Linux PSA attestation.
///
/// NOTE that Linux attestation is "mocked up" and totally insecure.  See the
/// attestation flow for AWS Nitro Enclaves for a secure attestation
/// implementation.  This is merely here for illustrative purposes.
static TOTALLY_INSECURE_ROOT_PRIVATE_KEY: [u8; 32] = [
    0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
    0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x05, 0x76, 0xa1, 0x44,
];

// Yes, I'm doing what you think I'm doing here. Each instance of the SGX root enclave
// will have the same public key. Yes, I'm embedding that key in the source
// code. I could come up with a complicated system for auto generating a key
// for each instance, and then use that key.
// That's what needs to be done if you want to productize this.
// That's not what I'm going to do for this research project
static TOTALLY_INSECURE_ROOT_PUBLIC_KEY: [u8; 65] = [
    0x4, 0x5f, 0x5, 0x5d, 0x39, 0xd9, 0xad, 0x60, 0x89, 0xf1, 0x33, 0x7e, 0x6c, 0xf9, 0x57, 0xe,
    0x6f, 0x84, 0x25, 0x5f, 0x16, 0xf8, 0xcd, 0x9c, 0xe4, 0xa0, 0xa2, 0x8d, 0x7a, 0x4f, 0xb7, 0xe4,
    0xd3, 0x60, 0x37, 0x2a, 0x81, 0x4f, 0x7, 0xc2, 0x5a, 0x24, 0x85, 0xbf, 0x47, 0xbc, 0x84, 0x47,
    0x40, 0xc5, 0x9b, 0xff, 0xff, 0xd2, 0x76, 0x32, 0x82, 0x4d, 0x76, 0x4d, 0xb4, 0x50, 0xee, 0x9f,
    0x22,
];

////////////////////////////////////////////////////////////////////////////////
// Initialization.
////////////////////////////////////////////////////////////////////////////////

/// Initializes the runtime manager, bringing up a new session manager instance.
fn initialize() -> RuntimeManagerResponse {
    if let Err(e) = init_session_manager() {
        error!(
            "Failed to initialize session manager.  Error produced: {:?}.",
            e
        );

        return RuntimeManagerResponse::Status(Status::Fail);
    }

    info!("Session manager initialized.");

    RuntimeManagerResponse::Status(Status::Success)
}

////////////////////////////////////////////////////////////////////////////////
// Native attestation (dummy implementation).
////////////////////////////////////////////////////////////////////////////////

/// Performs a dummy implementation of native attestation using the insecure
/// root private keys and computing the runtime manager hash.  If successful,
/// produces a PSA attestation token binding the CSR hash, runtime manager hash,
/// and challenge.
fn native_attestation(
    csr: Vec<u8>,
    challenge: Vec<u8>,
    runtime_manager_hash: &[u8],
) -> Result<Vec<u8>> {
    let csr_hash = sha256(&csr);

    let mut root_key_handle: u32 = 0;

    let ret = unsafe {
        psa_initial_attest_load_key(
            TOTALLY_INSECURE_ROOT_PRIVATE_KEY.as_ptr(),
            TOTALLY_INSECURE_ROOT_PRIVATE_KEY.len() as u64,
            &mut root_key_handle,
        )
    };

    if 0 != ret {
        return Err(anyhow!(RuntimeManagerError::UnsafeCallError(
            "psa_initial_attest_load_key",
            ret as u32,
        )));
    }

    let mut token = Vec::with_capacity(2048);
    let mut token_len: u64 = 0;

    // Section 3.2.1 of https://www.ietf.org/archive/id/draft-tschofenig-rats-psa-token-09.txt
    // EAT UEID of type RAND.
    // Length must be 33 bytes
    // first byte MUST be 0x01 (RAND)
    // next 32 bytes must be the hash of the key (Is this the public or private key? It's unclear, presume the public key because a hash of the private key could theoretically bleed info
    // about the private key)
    let public_key_hash = sha256(&TOTALLY_INSECURE_ROOT_PUBLIC_KEY);
    let mut enclave_name: Vec<u8> = Vec::new();
    enclave_name.push(0x01);
    enclave_name.extend_from_slice(&public_key_hash);

    let ret = unsafe {
        psa_initial_attest_get_token(
            runtime_manager_hash.as_ptr(),
            runtime_manager_hash.len() as u64,
            csr_hash.as_ptr() as *const u8,
            csr_hash.len() as u64,
            enclave_name.as_ptr() as *const c_char,
            enclave_name.len() as u64,
            challenge.as_ptr() as *const u8,
            challenge.len() as u64,
            token.as_mut_ptr() as *mut u8,
            token.capacity() as u64,
            &mut token_len as *mut u64,
        )
    };

    if 0 != ret {
        return Err(anyhow!(RuntimeManagerError::UnsafeCallError(
            "psa_initial_attest_get_token",
            ret as u32,
        )));
    }

    unsafe { token.set_len(token_len as usize) };

    let ret = unsafe { psa_initial_attest_remove_key(root_key_handle) };

    if 0 != ret {
        return Err(anyhow!(RuntimeManagerError::UnsafeCallError(
            "psa_initial_attest_remove_key",
            ret as u32,
        )));
    }

    Ok(token)
}

////////////////////////////////////////////////////////////////////////////////
// Entry point and message dispatcher.
////////////////////////////////////////////////////////////////////////////////

/// Main entry point for Linux: parses command line arguments to find the port
/// number we should be listening on for incoming connections from the Veracruz
/// server.  Parses incoming messages, and acts on them.
pub fn linux_main() -> Result<()> {
    env_logger::init();

    let matches = App::new("Linux runtime manager enclave")
        .author("The Veracruz Development Team")
        .arg(
            Arg::with_name("address")
                .short("a")
                .long("address")
                .takes_value(true)
                .required(true)
                .help("Address for connecting to Veracruz Server.")
                .value_name("ADDRESS"),
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

    let address = if let Some(address) = matches.value_of("address") {
        address
    } else {
        error!("No address given. Exiting...");
        return Err(anyhow!(RuntimeManagerError::CommandLineArguments));
    };

    let measurement = if let Some(measurement) = matches.value_of("runtime_manager_measurement") {
        measurement
    } else {
        error!("No measurement given. Exiting...");
        return Err(anyhow!(RuntimeManagerError::CommandLineArguments));
    };

    let mut measurement_bytes = vec![0u8; 32];

    if let Err(err) = decode_to_slice(measurement, &mut measurement_bytes) {
        error!(
            "Failed to decode Runtime Manager measurement ({}).  Error produced: {:?}.",
            measurement, err
        );
        return Err(anyhow!(RuntimeManagerError::CommandLineArguments));
    }

    let mut fd = TcpStream::connect(&address).map_err(|e| {
        error!("Could not connect to Veracruz Server on {}: {}", address, e);
        anyhow!(e)
    })?;
    info!("Connected to Veracruz Server on {}.", address);

    // Configure TCP to flush outgoing buffers immediately. This reduces latency
    // when dealing with small packets
    let _ = fd.set_nodelay(true);

    loop {
        info!("Listening for incoming message...");

        let received_buffer: Vec<u8> = receive_buffer(&mut fd).map_err(|err| {
            error!("Failed to receive message.  Error produced: {}.", err);
            anyhow!(err)
        })?;

        let received_message: RuntimeManagerRequest =
            deserialize(&received_buffer).map_err(|derr| {
                error!(
                    "Failed to deserialize received message.  Error produced: {}.",
                    derr
                );
                derr
            })?;

        info!("Received message: {:?}.", received_message);

        let return_message = match received_message {
            RuntimeManagerRequest::Attestation(challenge, _challenge_id) => {
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

                RuntimeManagerResponse::AttestationData(token, csr)
            }
            RuntimeManagerRequest::Initialize(policy_json, chain) => {
                info!("Loading policy: {}.", policy_json);

                if let Err(e) = load_policy(&policy_json) {
                    error!("Failed to load policy.  Error produced: {:?}.", e);

                    RuntimeManagerResponse::Status(Status::Fail)
                } else {
                    info!("Setting certificate chain.");

                    load_cert_chain(&chain).map_err(|e| {
                        error!("Failed to set certificate chain.  Error produced: {:?}.", e);

                        e
                    })?;

                    RuntimeManagerResponse::Status(Status::Success)
                }
            }
            RuntimeManagerRequest::NewTlsSession => {
                info!("Initiating new TLS session.");

                new_session()
                    .map(|session_id| RuntimeManagerResponse::TlsSession(session_id))
                    .unwrap_or_else(|e| {
                        error!(
                            "Could not initiate new TLS session.  Error produced: {:?}.",
                            e
                        );
                        RuntimeManagerResponse::Status(Status::Fail)
                    })
            }
            RuntimeManagerRequest::CloseTlsSession(session_id) => {
                info!("Closing TLS session.");

                close_session(session_id)
                    .map(|_e| RuntimeManagerResponse::Status(Status::Success))
                    .unwrap_or_else(|e| {
                        error!("Failed to close TLS session.  Error produced: {:?}.", e);
                        RuntimeManagerResponse::Status(Status::Fail)
                    })
            }
            RuntimeManagerRequest::GetTlsData(session_id) => {
                info!("Retrieving TLS data.");

                get_data(session_id)
                    .map(|(active, data)| RuntimeManagerResponse::TlsData(data, active))
                    .unwrap_or_else(|e| {
                        error!("Failed to retrieve TLS data.  Error produced: {:?}.", e);
                        RuntimeManagerResponse::Status(Status::Fail)
                    })
            }
            RuntimeManagerRequest::SendTlsData(session_id, tls_data) => {
                info!("Sending TLS data.");

                send_data(session_id, &tls_data)
                    .map(|_| RuntimeManagerResponse::Status(Status::Success))
                    .unwrap_or_else(|e| {
                        error!("Failed to send TLS data.  Error produced: {:?}.", e);
                        RuntimeManagerResponse::Status(Status::Fail)
                    })
            }
        };

        let return_buffer = serialize(&return_message).map_err(|serr| {
            error!(
                "Failed to serialize returned message.  Error produced: {}.",
                serr
            );
            serr
        })?;

        info!("Sending message: {:?}.", return_message);

        send_buffer(&mut fd, &return_buffer).map_err(|e| {
            error!("Failed to send message.  Error produced: {}.", e);
            e
        })?;
    }
}
