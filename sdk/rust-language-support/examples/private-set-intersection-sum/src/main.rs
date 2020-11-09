//! Private set intersection-sum example
//!
//! ## Context
//!
//! Inputs:                  an arbitrary number.
//! Assumed form of inputs:  an arbitrary number of Pinecone-encoded `HashSet<Person>` (see below).
//! Ensured form of outputs: A Pinecone-encoded `HashSet<Person>` (see below).
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use libveracruz::{data_description::write_result, host, return_code};
use serde::Deserialize;
use std::collections::HashSet;

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

#[derive(Deserialize, Debug, Eq, PartialEq)]
struct Input {
    /// The customers and the amount of money they spent.
    data: Data,
    /// The sample to test within the customer data set, above.  Note in a real
    /// application this would be assumed to originate from a principal distinct
    /// from the principal supplying the input data set.  Here, we simply assume
    /// that the two are provided by the same principal.
    sample: Sample,
}

/// Reads exactly one input, which is assumed to be a Pinecone-encoded `Input`
/// struct, as above.
fn read_inputs() -> Result<Input, i32> {
    if host::input_count() != 1 {
        return_code::fail_data_source_count()
    } else {
        let input = host::read_input(0).unwrap();
        Ok(match pinecone::from_bytes(input.as_slice()) {
            Err(_err) => return return_code::fail_bad_input(),
            Ok(s) => s,
        })
    }
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
/// intersection-sum before re-encoding it into Pinecone and returning.
fn main() -> return_code::Veracruz {
    let data = read_inputs()?;
    let result = set_intersection_sum(data.data, data.sample);
    write_result::<(usize, u64)>(result)
}
