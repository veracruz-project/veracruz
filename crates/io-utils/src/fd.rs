//! Common file descriptor-related material
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE.md` file in the Veracruz root directory for copyright
//! and licensing information.

use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};

/// Sends a `buffer` of data (by first transmitting an encoded length followed by
/// the data proper) to the file descriptor `fd`.
pub fn send_buffer<T>(mut fd: T, buffer: &[u8]) -> Result<()>
where
    T: std::io::Write,
{
    let len = buffer.len();

    // 1: Encode the data length and send it.
    {
        let mut buff = [0u8; 9];
        LittleEndian::write_u64(&mut buff, len as u64);
        fd.write_all(&buff)?;
    }

    // 2. Send the data proper.
    fd.write_all(&buffer)?;

    Ok(())
}

/// Reads a buffer of data from a file descriptor `fd` by first reading a length
/// of data, followed by the data proper.
pub fn receive_buffer<T>(mut fd: T) -> Result<Vec<u8>>
where
    T: std::io::Read,
{
    // 1. First read and decode the length of the data proper.
    let length = {
        let mut buff = [0u8; 9];
        fd.read_exact(&mut buff)?;
        LittleEndian::read_u64(&buff) as usize
    };

    // 2. Next, read the data proper.
    let mut buffer = vec![0u8; length];
    fd.read_exact(&mut buffer)?;

    Ok(buffer)
}
