//! Private set intersection example.
//!
//! ## Context
//!
//! Inputs:                  an arbitrary number.
//! Assumed form of inputs:  an arbitrary number of Pinecone-encoded `HashSet<Person>` (see below).
//! Ensured form of outputs: A Pinecone-encoded `HashSet<Person>` (see below).
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use libveracruz::{data_description::write_result, host, return_code};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The format of the contents of the input sets, encoding meta-data about an employee.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
struct Person {
    /// Name of the employee
    name: String,
    /// Internal ID of the employee
    employee_id: String,
    /// Age of the employee
    age: u8,
    /// Grade of the employee
    grade: u8,
}

/// Reads all inputs: each input is assumed to be a Bincode-encoded `HashSet<Person>`.  Function
/// returns a `Vec` of all hash-sets, one from each input provider.  Fails with
/// `return_code::ErrorCode::BadInput` if any input cannot be deserialized from Bincode.
fn read_inputs() -> Result<Vec<HashSet<Person>>, i32> {
    let inputs = host::read_all_inputs();

    let mut result: Vec<HashSet<Person>> = Vec::new();

    for i in inputs.into_iter() {
        match pinecone::from_bytes(&i) {
            Err(_err) => return return_code::fail_bad_input(),
            Ok(hsmap) => result.push(hsmap),
        }
    }

    Ok(result)
}

/// Intersects a list of HashSets together.
///
/// Returns an empty HashSet if the input list is empty.
fn set_intersection(sets: &[HashSet<Person>]) -> HashSet<Person> {
    let mut result = HashSet::new();

    if sets.len() == 0 {
        return result;
    } else {
        result = sets[0].clone();
        let tail = &sets[1..sets.len()];

        for set in tail.iter() {
            result = result.intersection(&set).cloned().collect();
        }

        result
    }
}

/// Entry point.  Reads an unbounded number of `HashSet<Person>` inputs and finds their
/// intersection, returning the result (again, a `HashSet<Person>`).  Assumes inputs and output are
/// encoded as Bincode.
fn main() -> Result<(), i32> {
    let inputs = read_inputs()?;
    let result = set_intersection(&inputs);
    write_result::<HashSet<Person>>(result)
}
