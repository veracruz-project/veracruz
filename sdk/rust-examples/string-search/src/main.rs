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
use std::{env, fs, process};

const INPUT_FILENAME: &'static str = "/input/random_search_text.txt";
const OUTPUT_FILENAME: &'static str = "/output/search_results.txt";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 1 {
        process::exit(1);
    }

    let query: String = args
        .get(0)
        .expect("Couldn't read the argument.")
        .to_string(); // Argument: To be searched for

    let file_vec: Vec<u8> = fs::read(INPUT_FILENAME)?;

    let filename: String = String::from_utf8_lossy(&file_vec).to_string(); // Input file: To be searched in

    let res_vec: Vec<&str> = search(&query, &filename);

    let mut ret: String = String::new();

    for line in res_vec {
        ret.push_str(line);
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
