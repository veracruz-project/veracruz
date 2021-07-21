//! Linux-specific material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::managers::{
    session_manager::{
	close_session, get_data, get_data_needed,
	init_session_manager, new_session, send_data
    },
    RuntimeManagerError,
};
use bincode::{deserialize, serialize};
use clap::{App, Arg};
use log::{error, info};
use std::net::TcpListener;
use veracruz_utils::platform::{
    linux::{receive_buffer, send_buffer},
    vm::{RuntimeManagerMessage, VMStatus},
};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Incoming address to listen on.  Note that `0.0.0.0` implies all addresses.
const INCOMING_ADDRESS: &'static str = "0.0.0.0";

////////////////////////////////////////////////////////////////////////////////
// Initialization.
////////////////////////////////////////////////////////////////////////////////

/// Initializes the runtime manager, bringing up a new session manager instance
/// with the `policy_json` encoding of the policy file, and generating an
/// attestation token from the `challenge` and `challenge_id` parameters.
fn initialize(policy_json: String, challenge: Vec<u8>, challenge_id: i32) -> RuntimeManagerMessage {
    if let Err(e) = init_session_manager(&policy_json) {
        error!(
            "Failed to initialize session manager.  Error produced: {:?}.",
            e
        );

        return RuntimeManagerMessage::Status(VMStatus::Fail);
    }

    info!("Session manager initialized with policy.");

    RuntimeManagerMessage::Status(VMStatus::Success)
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
        .get_matches();

    let port = if let Some(port) = matches.value_of("port") {
        info!("Received {} as port to listen on.", port);
        port
    } else {
        error!("Did not receive any port to listen on.  Exiting...");
        return Err(RuntimeManagerError::CommandLineArguments);
    };

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

    info!("TCP listener connected on {:?}.", client_addr);

    let mut abort = false;

    while !abort {
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

        info!("Received message: {:?}.", received_message);

        let return_message = match received_message {
            RuntimeManagerMessage::Initialize(policy_json, _challenge, _challenge_id) => {
                info!("Initializing enclave.");

                initialize(policy_json, _challenge, _challenge_id)
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
            RuntimeManagerMessage::ResetEnclave => {
                info!("Shutting down enclave.");

                abort = true;

                RuntimeManagerMessage::Status(VMStatus::Success)
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

        info!("Sending message: {:?}.", return_message);

        send_buffer(&mut fd, &return_buffer).map_err(|e| {
            error!("Failed to send message.  Error produced: {}.", e);
            RuntimeManagerError::IOError(e)
        })?;
    }

    Ok(())
}
