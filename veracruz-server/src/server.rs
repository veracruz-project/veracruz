//! The Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::common::*;
#[cfg(feature = "icecap")]
use crate::platforms::icecap::VeracruzServerIceCap as VeracruzServerEnclave;
#[cfg(feature = "linux")]
use crate::platforms::linux::veracruz_server_linux::VeracruzServerLinux as VeracruzServerEnclave;
#[cfg(feature = "nitro")]
use crate::platforms::nitro::veracruz_server_nitro::VeracruzServerNitro as VeracruzServerEnclave;
use bincode;
use policy_utils::policy::Policy;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

type EnclaveHandlerServer = Box<dyn crate::common::VeracruzServer + Sync + Send>;
type EnclaveHandler = Arc<Mutex<Option<EnclaveHandlerServer>>>;

fn veracruz_server_request(
    enclave_handler: EnclaveHandler,
    input_data: &[u8],
) -> Result<Vec<u8>, VeracruzServerError> {
    if input_data.len() < 4 {
        return Err(VeracruzServerError::InvalidRequestFormatError);
    }
    let session_id = match bincode::deserialize(&input_data).unwrap() {
        0 => {
            let mut enclave_handler_locked = enclave_handler.lock()?;

            let enclave = enclave_handler_locked
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;

            enclave.new_tls_session()?
        }
        n @ 1u32..=std::u32::MAX => n,
    };

    let received_data = &input_data[4..];

    let (active_flag, output_data_option) = {
        let mut enclave_handler_locked = enclave_handler.lock()?;

        let enclave = enclave_handler_locked
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?;

        enclave.tls_data(session_id, received_data.to_vec())?
    };

    // Shutdown the enclave
    if !active_flag {
        let mut enclave_handler_locked = enclave_handler.lock()?;

        // Drop the `VeracruzServer` object which triggers enclave shutdown
        *enclave_handler_locked = None;
    }

    // Response this request
    let result = match output_data_option {
        None => vec![],
        Some(output_data) => {
            let mut output = bincode::serialize(&session_id).unwrap();
            assert_eq!(output.len(), 4);
            for x in output_data {
                output.extend_from_slice(&x);
            }
            output
        }
    };
    Ok(result)
}

fn handle_veracruz_server_request(
    enclave_handler: EnclaveHandler,
    mut stream: TcpStream,
) -> Result<(), VeracruzServerError> {
    let mut buf = vec![];
    stream.read_to_end(&mut buf)?;
    let result = veracruz_server_request(enclave_handler, &buf)?;
    stream.write_all(&result)?;
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn serve_veracruz_server_requests(
    veracruz_server_url: &str,
    enclave_handler: EnclaveHandler,
) -> Result<(), VeracruzServerError> {
    let listener = TcpListener::bind(veracruz_server_url)?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            let enclave_handler = enclave_handler.clone();
            thread::spawn(|| {
                let _ = handle_veracruz_server_request(enclave_handler, stream);
            });
        }
    });
    Ok(())
}

/// A server that listens on one TCP port.
/// This function returns when the spawned thread is listening.
pub fn server(policy_json: &str) -> Result<(), VeracruzServerError> {
    let policy: Policy = serde_json::from_str(policy_json)?;
    #[allow(non_snake_case)]
    let VERACRUZ_SERVER: EnclaveHandler = Arc::new(Mutex::new(Some(Box::new(
        VeracruzServerEnclave::new(policy_json)?,
    ))));

    serve_veracruz_server_requests(&policy.veracruz_server_url(), VERACRUZ_SERVER.clone())?;
    Ok(())
}
