//! Pipeline Example : Remove Divisible by 2 or 3
//!
//! ## Context
//!
//! Remove all number that are divisible by 2 or 3
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


const FILENAME: &'static str = "/output/number-set.txt"; 

fn main() -> anyhow::Result<()>{

    let content = String::from_utf8(fs::read(FILENAME)?)?;

    let num_vec: Vec<u32> = content
        .trim()
        .split(",")
        .map(|x| x.parse::<u32>().unwrap())
        .collect();

    let filtered_vec: Vec<u32> = num_vec
        .into_iter()
        .filter(|x| x % 2 != 0 && x % 3 != 0).collect::<Vec<_>>();

    let content: String = filtered_vec
        .iter()
        .map(|x| x.to_string() + ",")
        .collect();

    fs::write(FILENAME, content)?;
    
    Ok(())
}

