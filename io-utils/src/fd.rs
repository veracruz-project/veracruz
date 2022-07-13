//! Common file descriptor-related material
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for copyright
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

        let mut sent_bytes = 0;

        while sent_bytes < 9 {
            sent_bytes += fd.write(&buff[sent_bytes..9])?;
        }
    }

    // 2. Send the data proper.
    {
        let mut sent_bytes = 0;

        while sent_bytes < len {
            sent_bytes += fd.write(&buffer[sent_bytes..len])?;
        }
    }

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
        let mut received_bytes = 0;

        while received_bytes < 9 {
            received_bytes += fd.read(&mut buff[received_bytes..9])?;
        }

        LittleEndian::read_u64(&buff) as usize
    };

    // 2. Next, read the data proper.
    let mut buffer = vec![0u8; length];

    {
        let mut received_bytes = 0;

        while received_bytes < length {
            received_bytes += fd.read(&mut buffer[received_bytes..length])?;
        }
    }

    Ok(buffer)
}
