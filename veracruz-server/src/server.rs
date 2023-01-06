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
use std::thread;

// This buffer size gave close to optimal performance for
// copying a 100 MB file into the enclave on Linux:
const BUFFER_SIZE: usize = 32768;

fn handle_request(
    mut enclave_handler: VeracruzServer,
    mut stream: TcpStream,
) -> std::io::Result<()> {
    let mut session = enclave_handler
        .new_session()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "xx"))?;
    // From enclave:
    {
        let mut session = session.clone();
        let mut stream = stream.try_clone().unwrap();
        thread::spawn(move || loop {
            let mut buf = [0; BUFFER_SIZE];
            let n = session.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[0..n]).unwrap();
        });
    }
    // To enclave:
    loop {
        let mut buf = [0; BUFFER_SIZE];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        session.write_all(&buf[0..n])?;
    }
    Ok(())
}

/// A server that listens on one TCP port.
/// This function returns when the spawned thread is listening.
pub fn server(policy_json: &str) -> Result<(), VeracruzServerError> {
    let policy: Policy = serde_json::from_str(policy_json)?;
    let enclave_handler = VeracruzServer::new(policy_json)?;
    let listener = TcpListener::bind(&policy.veracruz_server_url())?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            let enclave_handler = enclave_handler.clone();
            thread::spawn(|| {
                handle_request(enclave_handler, stream).unwrap();
            });
        }
    });
    Ok(())
}
