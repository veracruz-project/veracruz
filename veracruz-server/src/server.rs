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
use policy_utils::policy::Policy;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

type EnclaveHandlerServer = Box<dyn crate::common::VeracruzServer + Sync + Send>;
type EnclaveHandler = Arc<Mutex<Option<EnclaveHandlerServer>>>;

// This buffer size gave close to optimal performance for
// copying a 100 MB file into the enclave on Linux:
const BUFFER_SIZE: usize = 32768;

fn handle_veracruz_server_request(
    enclave_handler: EnclaveHandler,
    mut stream: TcpStream,
) -> Result<(), VeracruzServerError> {
    let session_id = {
        let mut enclave_handler_locked = enclave_handler.lock()?;
        let enclave = enclave_handler_locked
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
        enclave.new_tls_session()?
    };

    loop {
        let mut buf = [0; BUFFER_SIZE];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let (active_flag, output_data_option) = {
            let mut enclave_handler_locked = enclave_handler.lock()?;
            let enclave = enclave_handler_locked
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
            enclave.tls_data(session_id, buf[0..n].to_vec())?
        };

        // Shutdown the enclave
        if !active_flag {
            let mut enclave_handler_locked = enclave_handler.lock()?;
            // Drop the `VeracruzServer` object which triggers enclave shutdown
            *enclave_handler_locked = None;
        }

        // Response this request
        for x1 in output_data_option {
            for x in x1 {
                stream.write_all(&x)?;
            }
        }
    }

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
