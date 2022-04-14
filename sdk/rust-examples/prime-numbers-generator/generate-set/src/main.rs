//! Prime Numbers Generator: Generate the number set
//!
//! ## Context
//!
//! Generate all numbers from 2 to the specified upper limit
//! 
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use std::fs;
use anyhow;

const OUTPUT_FILENAME: &'static str = "/output/number-set.txt";

fn main() -> anyhow::Result<()> {
    let mut set: Vec<u32> = Vec::new();

    let args: Vec<String> = std::env::args().collect();
    let upper_limit = args.get(0)
        .unwrap()
        .to_owned()
        .parse::<u32>()?;

    for i in 2..=upper_limit {
        set.push(i);
    }

    let mut set_str: String = set
        .iter()
        .map(|num| num.to_string() + ",")
        .collect();

    set_str.pop();
    set_str.push('\n');

    fs::write(OUTPUT_FILENAME, set_str)?;

    Ok(())
}
