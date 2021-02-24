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

use libveracruz::{data_description::write_result, host, return_code};

fn main() -> return_code::Veracruz {
    let init_value = read_init_value()?;
    let last_result = read_last_result()?.unwrap_or(0.0);
    let (stream1, stream2) = read_stream()?;
    write_result::<f64>(init_value + stream1 + stream2 + last_result)
}

fn read_init_value() -> Result<f64, i32> {
    if host::input_count() != 1 {
        return return_code::fail_data_source_count();
    } else {
        let input = host::read_input(0).unwrap();

        match pinecone::from_bytes(&input) {
            Err(_err) => return_code::fail_bad_input(),
            Ok(s) => Ok(s),
        }
    }
}

fn read_last_result() -> Result<Option<f64>, i32> {
    //Ok(None)
    match host::read_previous_result() {
        host::HCallReturnCode::Success(previous_result) => match previous_result {
            None => Ok(None),
            Some(p) => Ok(Some(match pinecone::from_bytes(&p) {
                Err(_err) => return return_code::fail_bad_input(),
                Ok(s) => s,
            })),
        },
        _otherwise => return return_code::fail_bad_input(),
    }
}

fn read_stream() -> Result<(f64, f64), i32> {
    if host::stream_count() < 2 {
        return return_code::fail_data_source_count();
    } else {
        let stream1 = host::read_stream(0).unwrap();
        let stream2 = host::read_stream(1).unwrap();

        let n1: f64 = pinecone::from_bytes(&stream1).unwrap();
        let n2: f64 = pinecone::from_bytes(&stream2).unwrap();
        Ok((n1, n2))
    }
}
