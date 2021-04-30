//! Accumulating two streams of values.
//!
//!
//! ## Context
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use wasi_types::ErrNo;
use std::{fs, fs::File, process::exit, io::{Read, ErrorKind, SeekFrom, Seek}};

fn main() {
    if let Err(e) = compute() {
        exit((e as u16).into());
    }
}

fn compute() -> Result<(),ErrNo> {
    let (count, last_result_or_init) = read_last_result_or_init()?;
    let (stream1, stream2) = read_stream((count * 8) as u64)?;
    let result_encode = pinecone::to_vec::<(u64, f64)>(&(count + 1, (last_result_or_init + stream1 + stream2))).map_err(|_| ErrNo::Proto)?;
    fs::write("/output", result_encode)?;
    Ok(())
}

fn read_last_result_or_init() -> Result<(u64, f64), ErrNo> {
    let mut file = match File::open("/output") {
        Ok(o) => o,
        Err(e) => match e.kind() {
            // Not found the last result, read the init.
            ErrorKind::NotFound => {
                let input = fs::read("/input-0")?;
                let init = pinecone::from_bytes(&input).map_err(|_|ErrNo::Proto)?;
                return Ok((0, init));
            }
            _kind => return Err(e.into()),
            },
    };

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    pinecone::from_bytes(&data).map_err(|_| ErrNo::Proto)
}

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
