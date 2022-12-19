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
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

type EnclaveHandlerServer = Box<dyn crate::common::VeracruzServer + Sync + Send>;
type EnclaveHandler = Arc<Mutex<Option<EnclaveHandlerServer>>>;

// This buffer size gave close to optimal performance for
// copying a 100 MB file into the enclave on Linux:
const BUFFER_SIZE: usize = 32768;

struct NewEnclaveHandler(EnclaveHandler);

impl NewEnclaveHandler {
    fn new(policy: &str) -> VeracruzServerResult<Self> {
        Ok(NewEnclaveHandler(Arc::new(Mutex::new(Some(Box::new(
            VeracruzServerEnclave::new(policy)?,
        ))))))
    }
    fn clone(&self) -> Self {
        NewEnclaveHandler(self.0.clone())
    }
    fn new_session(&mut self) -> VeracruzServerResult<NewEnclaveSession> {
        Ok(NewEnclaveSession {
            enclave: self.0.clone(),
            session_id: self
                .0
                .lock()?
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?
                .new_tls_session()?,
            buffer: Arc::new((Mutex::new(vec![]), Condvar::new())),
        })
    }
}

struct NewEnclaveSession {
    enclave: EnclaveHandler,
    session_id: u32,
    buffer: Arc<(Mutex<Vec<u8>>, Condvar)>,
}

impl NewEnclaveSession {
    fn clone(&self) -> Self {
        NewEnclaveSession {
            enclave: self.enclave.clone(),
            session_id: self.session_id,
            buffer: self.buffer.clone(),
        }
    }
}

impl Read for NewEnclaveSession {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        if buf.len() == 0 {
            Ok(0)
        } else {
            let mut buffer = self.buffer.0.lock().unwrap();
            while buffer.len() == 0 {
                buffer = self.buffer.1.wait(buffer).unwrap();
            }
            let n = std::cmp::min(buf.len(), buffer.len());
            buf[0..n].clone_from_slice(&buffer[0..n]);
            buffer.drain(0..n);
            Ok(n)
        }
    }
}

impl Write for NewEnclaveSession {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        if buf.len() > 0 {
            let (active, output) = self
                .enclave
                .lock()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "xx"))?
                .as_mut()
                .ok_or(std::io::Error::new(std::io::ErrorKind::Other, "xx"))?
                .tls_data(self.session_id, buf.to_vec())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "xx"))?;
            if !active {
                let mut mb_enclave = self
                    .enclave
                    .lock()
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "xx"))?;
                *mb_enclave = None;
            }
            let mut buffer = self
                .buffer
                .0
                .lock()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "xx"))?;
            for x1 in output {
                for mut x in x1 {
                    buffer.append(&mut x);
                }
            }
            self.buffer.1.notify_one();
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}

fn handle_request(
    mut enclave_handler: NewEnclaveHandler,
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
    let enclave_handler = NewEnclaveHandler::new(policy_json)?;
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
