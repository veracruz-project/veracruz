//! Mini Grep
//!
//! ## Context
//!
//! Searches for the argument inside the input file, and prints the result.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use anyhow::{self, Ok};
use std::fs;

const INPUT_FILENAME: &'static str = "/input/hello-world-1.dat";
const OUTPUT_FILENAME: &'static str = "/output/search_results.dat";

fn main() -> anyhow::Result<()> {
    let query = std::env::var("QUERY")?.to_string(); // search argument

    let file_vec: Vec<u8> = fs::read(INPUT_FILENAME)?;

    let filename: String = String::from_utf8_lossy(&file_vec).to_string(); // Input file: To be searched in

    let res_vec: Vec<&str> = search(&query, &filename);

    let mut ret: String = String::new();

    for line in res_vec {
        ret.push_str(line);
        ret.push_str("\n");
    }

    fs::write(OUTPUT_FILENAME, ret)?;

    Ok(())
}

fn search<'a>(query: &str, contents: &'a str) -> Vec<&'a str> {
    let mut results = Vec::new();

    for line in contents.lines() {
        if line.contains(query) {
            results.push(line);
        }
    }

    results
}
