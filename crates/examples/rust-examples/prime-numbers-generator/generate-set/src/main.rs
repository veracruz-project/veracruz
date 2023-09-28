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
//! See the file `LICENSE.md` in the Veracruz root directory for licensing and
//! copyright information.

use anyhow;
use std::fs;

const OUTPUT_FILENAME: &'static str = "./output/number-set.txt";

fn main() -> anyhow::Result<()> {
    let mut set: Vec<u32> = Vec::new();

    let upper_limit = std::env::var("LIMIT")?.parse::<u32>()?;

    for i in 2..=upper_limit {
        set.push(i);
    }

    let mut set_str: String = set
        .iter()
        .map(|num| num.to_string())
        .collect::<Vec<_>>()
        .join(",");

    set_str.push('\n');

    fs::write(OUTPUT_FILENAME, set_str)?;

    Ok(())
}
