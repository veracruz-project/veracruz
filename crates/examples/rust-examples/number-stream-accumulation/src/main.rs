//! Accumulating two streams of values.
//!
//!
//! ## Context
//!
//! Add an initial float-64 number and two stream of float-64 numbers.
//! The result is a pair of the number of (function) calls and the final accumulation result.
//!
//! Inputs:                  One.
//! Assumed 'input-0'  : A Postcard-encoded Rust `f64` value.
//! Assumed 'stream-0' : A Postcard-encoded Rust vector of  `f64` values.
//! Assumed 'stream-2' : A Postcard-encoded Rust vector of  `f64` values.
//! Ensured 'output'   : A Postcard-encoded pair of `u64` and `f64`.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.md` in the Veracruz root directory for licensing and
//! copyright information.

use anyhow::anyhow;
use std::{
    fs,
    fs::File,
    io::{ErrorKind, Read, Seek, SeekFrom},
};

/// Read the initial value, if there is no previous result at 'output' file.
/// Otherwise, read the previous result.
/// Read two new numbers from 'stream-0' and 'stream-1'.
/// Add the two new numbers, and either the initial value or the previous result
/// as the new result and write it to 'output'.
/// The result also contains the number of function calls, which
/// track the starting point of the next nunbers in 'stream-0' and 'stream-1'.
fn main() -> anyhow::Result<()> {
    let (count, last_result_or_init) = read_last_result_or_init()?;
    let (stream1, stream2) = read_stream((count * 8) as u64)?;
    let result_encode = postcard::to_allocvec::<(u64, f64)>(&(
        count + 1,
        (last_result_or_init + stream1 + stream2),
    ))?;
    fs::write("./output/accumulation.dat", result_encode)?;
    Ok(())
}

/// Read 'output' if exists. Otherwise read 'input-0'.
fn read_last_result_or_init() -> anyhow::Result<(u64, f64)> {
    let mut file = match File::open("/output/accumulation.dat") {
        Ok(o) => o,
        Err(e) => match e.kind() {
            // Not found the last result, read the init.
            ErrorKind::NotFound => {
                let input = fs::read("/input/number-stream-init.dat")?;
                let init = postcard::from_bytes(&input)?;
                return Ok((0, init));
            }
            _kind => return Err(anyhow!(e)),
        },
    };

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(postcard::from_bytes(&data)?)
}

/// Read from 'stream-0' and 'stream-1' at `offset`
fn read_stream(offset: u64) -> anyhow::Result<(f64, f64)> {
    let mut stream0 = File::open("./input/number-stream-1.dat")?;
    stream0.seek(SeekFrom::Start(offset))?;
    let mut data0 = Vec::new();
    stream0.read_to_end(&mut data0)?;
    let n1: f64 = postcard::from_bytes(&data0)?;

    let mut stream1 = File::open("./input/number-stream-2.dat")?;
    stream1.seek(SeekFrom::Start(offset))?;
    let mut data1 = Vec::new();
    stream1.read_to_end(&mut data1)?;
    let n2: f64 = postcard::from_bytes(&data1)?;

    Ok((n1, n2))
}
