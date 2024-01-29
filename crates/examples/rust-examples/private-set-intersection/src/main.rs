//! Private set intersection example.
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
//! ## Copyright
//!
//! See the file `LICENSE.md` in the Veracruz root directory for licensing and
//! copyright information.

use anyhow;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs};

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
fn read_inputs() -> anyhow::Result<Vec<HashSet<Person>>> {
    let input0 = fs::read("./input/private-set-1.dat")?;
    let data0 = postcard::from_bytes(&input0)?;
    let input1 = fs::read("./input/private-set-2.dat")?;
    let data1 = postcard::from_bytes(&input1)?;
    Ok(vec![data0, data1])
}

/// Intersects a list of HashSets together.
///
/// Returns an empty HashSet if the input list is empty.
fn set_intersection(sets: &[HashSet<Person>]) -> HashSet<Person> {
    let mut result = HashSet::new();

    if sets.is_empty() {
        result
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
fn main() -> anyhow::Result<()> {
    let inputs = read_inputs()?;
    let result = set_intersection(&inputs);
    let result_encode = postcard::to_allocvec::<HashSet<Person>>(&result)?;
    fs::write("./output/private-set.dat", result_encode)?;
    Ok(())
}
