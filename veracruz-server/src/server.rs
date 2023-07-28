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
use policy_utils::policy::Policy;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};

type EnclaveHandler<T> = Arc<Mutex<Option<T>>>;

// This buffer size gave close to optimal performance for
// copying a 100 MB file into the enclave on Linux:
const BUFFER_SIZE: usize = 32768;

fn handle_veracruz_server_request<T: VeracruzServer + Sync + Send>(
    enclave_handler: EnclaveHandler<T>,
    mut stream: TcpStream,
) -> Result<(), VeracruzServerError> {
    let session_id = {
        let mut enclave_handler_locked = enclave_handler.lock()?;
        let enclave = enclave_handler_locked
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?;
        new_tls_session(&mut *enclave)?
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
            tls_data(session_id, buf[0..n].to_vec(), &mut *enclave)?
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

pub fn new_tls_session<T: VeracruzServer + Send + Sync + ?Sized>(
    enclave: &mut T,
) -> Result<u32, VeracruzServerError> {
    let nls_message = RuntimeManagerRequest::NewTlsSession;
    let nls_buffer = bincode::serialize(&nls_message)?;
    enclave.send_buffer(&nls_buffer)?;

    let received_buffer: Vec<u8> = enclave.receive_buffer()?;

    let received_message: RuntimeManagerResponse = bincode::deserialize(&received_buffer)?;
    let session_id = match received_message {
        RuntimeManagerResponse::TlsSession(sid) => sid,
        _ => {
            return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                received_message,
            ))
        }
    };
    Ok(session_id)
}

pub fn tls_data<T: VeracruzServer + Send + Sync + ?Sized>(
    session_id: u32,
    input: Vec<u8>,
    enclave: &mut T,
) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
    let std_message: RuntimeManagerRequest = RuntimeManagerRequest::SendTlsData(session_id, input);
    let std_buffer: Vec<u8> = bincode::serialize(&std_message)?;

    enclave.send_buffer(&std_buffer)?;

    let received_buffer: Vec<u8> = enclave.receive_buffer()?;

    let received_message: RuntimeManagerResponse = bincode::deserialize(&received_buffer)?;
    match received_message {
        RuntimeManagerResponse::Status(status) => match status {
            Status::Success => (),
            _ => return Err(VeracruzServerError::Status(status)),
        },
        _ => {
            return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                received_message,
            ))
        }
    }

    let mut active_flag = true;
    let mut ret_array = Vec::new();
    loop {
        let gtd_message = RuntimeManagerRequest::GetTlsData(session_id);
        let gtd_buffer: Vec<u8> = bincode::serialize(&gtd_message)?;

        enclave.send_buffer(&gtd_buffer)?;

        let received_buffer: Vec<u8> = enclave.receive_buffer()?;

        let received_message: RuntimeManagerResponse = bincode::deserialize(&received_buffer)?;
        match received_message {
            RuntimeManagerResponse::TlsData(data, alive) => {
                if !alive {
                    active_flag = false
                }
                if data.len() == 0 {
                    break;
                }
                ret_array.push(data);
            }
            _ => return Err(VeracruzServerError::Status(Status::Fail)),
        }
    }

    Ok((
        active_flag,
        if !ret_array.is_empty() {
            Some(ret_array)
        } else {
            None
        },
    ))
}

fn serve_veracruz_server_requests<T: VeracruzServer + Sync + Send + 'static>(
    veracruz_server_url: &str,
    enclave_handler: EnclaveHandler<T>,
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
pub fn server<T: VeracruzServer + Send + Sync + 'static>(
    policy_json: &str,
    server: T,
) -> Result<(), VeracruzServerError> {
    let policy: Policy = serde_json::from_str(policy_json)?;
    #[allow(non_snake_case)]
    let VERACRUZ_SERVER: EnclaveHandler<T> = Arc::new(Mutex::new(Some(server)));

    serve_veracruz_server_requests(&policy.veracruz_server_url(), VERACRUZ_SERVER.clone())?;
    Ok(())
}
