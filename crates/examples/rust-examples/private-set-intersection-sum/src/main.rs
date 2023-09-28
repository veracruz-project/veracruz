//! Private set intersection-sum example
//!
//! ## Context
//!
//! Inputs:                  an arbitrary number.
//! Assumed form of inputs:  an arbitrary number of Postcard-encoded `HashSet<Person>` (see below).
//! Ensured form of outputs: A Postcard-encoded `HashSet<Person>` (see below).
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::anyhow;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

/// The identifier of each customer, a pair of `u64` values.
type Id = (u64, u64);
/// The value associated with each customer.  This can be assumed to be e.g. the amount
/// of money spent on the retailer's website.  Represented here as a `u32` value.
type Value = u32;
/// A data entry consists of a unique customer ID paired with a `Value`.
type Data = Vec<(Id, Value)>;
/// A sample is simply a collection of unique customer identifiers.
type Sample = Vec<Id>;

///////////////////////////////////////////////////////////////////////////////
// Reading inputs.
///////////////////////////////////////////////////////////////////////////////

/// Reads exactly one input, which is assumed to be a Postcard-encoded `Input`
/// struct, as above.
fn read_inputs<T: AsRef<Path>>(path: T) -> anyhow::Result<(Data, Sample)> {
    let mut sample_path = path.as_ref().to_path_buf();
    sample_path.push("sample.dat");
    let sample = fs::read(sample_path)?;
    let sample = postcard::from_bytes(sample.as_slice())?;

    let mut data_path = path.as_ref().to_path_buf();
    data_path.push("data.dat");
    let data = fs::read(data_path)?;
    let data = postcard::from_bytes(data.as_slice())?;
    Ok((data, sample))
}

/// Computes the set intersection-sum, returning the number of elements the sample and input
/// dataset have in common, along with the total value of the sum of values associated with each
/// customer that appears in the set intersection.
fn set_intersection_sum(data: Vec<((u64, u64), u32)>, sample: Vec<(u64, u64)>) -> (usize, u64) {
    let sample_set: HashSet<(u64, u64)> = sample.into_iter().collect();
    data.iter().fold((0, 0), |(count, sum), (id, value)| {
        if sample_set.contains(&id) {
            (count + 1, sum + *value as u64)
        } else {
            (count, sum)
        }
    })
}

/// The program entry point: reads exactly one input, decodes it and computes the set
/// intersection-sum before re-encoding it into Postcard and returning.
fn main() -> anyhow::Result<()> {
    for path in fs::read_dir("./input/private-set-inter-sum/")? {
        let path = path?.path();
        let (data, sample) = read_inputs(&path)?;
        let result = set_intersection_sum(data, sample);
        let result_encode = postcard::to_allocvec::<(usize, u64)>(&result)?;
        fs::create_dir_all("./output/private-set-inter-sum/")?;
        let mut output = PathBuf::from("./output/private-set-inter-sum/");
        output.push(path.file_name().ok_or(anyhow!("cannot get file name"))?);
        fs::write(output, result_encode)?;
    }
    Ok(())
}
