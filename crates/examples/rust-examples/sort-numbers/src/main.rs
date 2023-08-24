//! Sorting Numbers Example
//!
//! ## Context
//!
//! Read an input of unsorted_numbers.txt, sort them and write to sorted_numbers.txt
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
use std::fs;

const INPUT_FILENAME: &'static str = "/output/unsorted_numbers.txt";
const OUTPUT_FILENAME: &'static str = "/output/sorted_numbers.txt";

fn main() -> anyhow::Result<()> {
    let file_vec = fs::read(INPUT_FILENAME)?;

    let content = String::from_utf8_lossy(&file_vec).to_string();

    let mut num_vec: Vec<u32> = content
        .trim()
        .split(",")
        .map(|x| x.parse::<u32>().unwrap())
        .collect();

    num_vec.sort();

    let mut vec_to_str: String = num_vec.iter().map(|num| num.to_string() + ",").collect();
    // deleting last comma, and appending the string with "\n"
    vec_to_str.pop();
    vec_to_str.push('\n');

    fs::write(OUTPUT_FILENAME, vec_to_str)?;
    Ok(())
}
