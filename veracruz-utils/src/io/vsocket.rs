//! Virtual sockets
//!
//! This is used in the AWS Nitro backend.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use nix::{
    sys::socket::{
        connect, setsockopt, shutdown, socket, AddressFamily, sockopt::{ReuseAddr, ReusePort}, Shutdown, SockAddr, SockFlag, SockType,
    },
    unistd::close,
};
use std::{
    os::unix::io::{AsRawFd, RawFd},
    thread::sleep,
    time::Duration,
};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Maximum number of connection attempts to make before erroring out
const MAX_CONNECTION_ATTEMPTS: usize = 5;

////////////////////////////////////////////////////////////////////////////////
// Virtual sockets.
////////////////////////////////////////////////////////////////////////////////

/// A struct containing the details of a VSOCK.
pub struct VsockSocket {
    /// The file handle of the VSOCK.
    socket_fd: RawFd,
}

impl VsockSocket {
    #[inline]
    /// Create a new VsockSocket from a RawFd for a io.
    fn new(socket_fd: RawFd) -> Self {
        VsockSocket { socket_fd }
    }

    /// Initiate a connection on an AF_VSOCK io.  Fails if the connection
    /// cannot be made after `MAX_CONNECTION_ATTEMPTS` attempts.  Uses
    /// exponential back-off to wait between different attempts to connect.
    pub fn connect<T>(cid: T, port: T) -> Result<VsockSocket, nix::Error>
    where
        T: Into<u32>,
    {
        let sockaddr = SockAddr::new_vsock(cid.into(), port.into());
        // Just a placeholder!
        let mut err: nix::Error = nix::Error::UnsupportedOperation;

        for i in 0..MAX_CONNECTION_ATTEMPTS {
            let vsocket = VsockSocket::new(socket(
                AddressFamily::Vsock,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )?);

            setsockopt(vsocket.as_raw_fd(), ReuseAddr, &true)?;
            setsockopt(vsocket.as_raw_fd(), ReusePort, &true)?;

            match connect(vsocket.as_raw_fd(), &sockaddr) {
                Ok(_) => return Ok(vsocket),
                Err(e) => err = e,
            }

            // Exponentially backoff before retrying to connect to the io
            sleep(Duration::from_secs(1 << i));
        }

        // In case of success this should never be reached.
        Err(err)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations.
////////////////////////////////////////////////////////////////////////////////

impl Drop for VsockSocket {
    /// Drop a io by closing it. If it fails, report a message, but don't
    /// do anything else (it could fail because it's not connected).
    fn drop(&mut self) {
        // Do nothing on failure. It's non fatal and a warning message is just confusing
        shutdown(self.socket_fd, Shutdown::Both).unwrap_or_else(|_| ());
        close(self.socket_fd).unwrap_or_else(|e| eprintln!("Failed to close io: {:?}", e));
    }
}

impl AsRawFd for VsockSocket {
    #[inline]
    /// Extract the raw RadFd from the VsockSocket
    fn as_raw_fd(&self) -> RawFd {
        self.socket_fd
    }
}
