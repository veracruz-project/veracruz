//! Virtual socket handler for Veracruz
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use nix::sys::socket::{connect, shutdown, socket};
use nix::sys::socket::{AddressFamily, Shutdown, SockAddr, SockFlag, SockType};
use nix::unistd::close;
use std::os::unix::io::{AsRawFd, RawFd};

/// Maximum number of connection attempts to make before erroring out
const MAX_CONNECTION_ATTEMPTS: usize = 5;

/// A struct containing the details of a VSOCK
pub struct VsockSocket {
    socket_fd: RawFd,
}

impl VsockSocket {
    /// create a new VsockSocket from a RawFd for a socket
    fn new(socket_fd: RawFd) -> Self {
        VsockSocket { socket_fd }
    }
}

impl Drop for VsockSocket {
    /// Drop a socket by closing it. If it fails, report a message, but don't
    /// do anything else (it could fail because it's not connected)
    fn drop(&mut self) {
        shutdown(self.socket_fd, Shutdown::Both).unwrap_or_else(|_| ()); // Do nothing on failure. It's non fatal and a warning message is just confusing
        close(self.socket_fd).unwrap_or_else(|e| eprintln!("Failed to close socket: {:?}", e));
    }
}

impl AsRawFd for VsockSocket {
    /// Extract the raw RadFd from the VsockSocket
    fn as_raw_fd(&self) -> RawFd {
        self.socket_fd
    }
}

/// Initiate a connection on an AF_VSOCK socket
pub fn vsock_connect(cid: u32, port: u32) -> Result<VsockSocket, nix::Error> {
    let sockaddr = SockAddr::new_vsock(cid, port);
    let mut err: nix::Error = nix::Error::UnsupportedOperation; // just a placeholder

    for i in 0..MAX_CONNECTION_ATTEMPTS {
        let vsocket = VsockSocket::new(socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )?);
        match connect(vsocket.as_raw_fd(), &sockaddr) {
            Ok(_) => return Ok(vsocket),
            Err(e) => err = e,
        }

        // Exponentially backoff before retrying to connect to the socket
        std::thread::sleep(std::time::Duration::from_secs(1 << i));
    }

    // in case of success, this should never be reached
    Err(err)
}
