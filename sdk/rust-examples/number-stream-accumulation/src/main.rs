//! Accumulating two streams of values.
//!
//!
//! ## Context
//!
//! Add an initial float-64 number and two stream of float-64 numbers. 
//! The result is a pair of the number of (function) calls and the final accumulation result.
//!
//! Inputs:                  One.
//! Assumed 'input-0'  : A Pinecone-encoded Rust `f64` value.
//! Assumed 'stream-0' : A Pinecone-encoded Rust vector of  `f64` values.
//! Assumed 'stream-2' : A Pinecone-encoded Rust vector of  `f64` values.
//! Ensured 'output'   : A Pinecone-encoded pair of `u64` and `f64`.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use std::{
    fs,
    fs::File,
    io::{ErrorKind, Read, Seek, SeekFrom},
    process::exit,
};
use wasi_types::ErrNo;

/// Entry point
fn main() {
    if let Err(e) = compute() {
        exit((e as u16).into());
    }
}

/// Read the initial value, if there is no previous result at 'output' file. 
/// Otherwise, read the previous result.
/// Read two new numbers from 'stream-0' and 'stream-1'.
/// Add the two new numbers, and either the initial value or the previous result 
/// as the new result and write it to 'output'.
/// The result also contains the number of function calls, which 
/// track the starting point of the next nunbers in 'stream-0' and 'stream-1'.
fn compute() -> Result<(), ErrNo> {
    let (count, last_result_or_init) = read_last_result_or_init()?;
    let (stream1, stream2) = read_stream((count * 8) as u64)?;
    let result_encode =
        pinecone::to_vec::<(u64, f64)>(&(count + 1, (last_result_or_init + stream1 + stream2)))
            .map_err(|_| ErrNo::Proto)?;
    fs::write("/output", result_encode)?;
    Ok(())
}

/// Read 'output' if exists. Othewise read 'input-0'.
fn read_last_result_or_init() -> Result<(u64, f64), ErrNo> {
    let mut file = match File::open("/output") {
        Ok(o) => o,
        Err(e) => match e.kind() {
            // Not found the last result, read the init.
            ErrorKind::NotFound => {
                let input = fs::read("/input-0")?;
                let init = pinecone::from_bytes(&input).map_err(|_| ErrNo::Proto)?;
                return Ok((0, init));
            }
            _kind => return Err(e.into()),
        },
    };

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    pinecone::from_bytes(&data).map_err(|_| ErrNo::Proto)
}

/// Read from 'stream-0' and 'stream-1' at `offset`
fn read_stream(offset: u64) -> Result<(f64, f64), ErrNo> {
    let mut stream0 = File::open("/stream-0")?;
    stream0.seek(SeekFrom::Start(offset))?;
    let mut data0 = Vec::new();
    stream0.read_to_end(&mut data0)?;
    let n1: f64 = pinecone::from_bytes(&data0).map_err(|_| ErrNo::Proto)?;

    let mut stream1 = File::open("/stream-1")?;
    stream1.seek(SeekFrom::Start(offset))?;
    let mut data1 = Vec::new();
    stream1.read_to_end(&mut data1)?;
    let n2: f64 = pinecone::from_bytes(&data1).map_err(|_| ErrNo::Proto)?;

    Ok((n1, n2))
}
