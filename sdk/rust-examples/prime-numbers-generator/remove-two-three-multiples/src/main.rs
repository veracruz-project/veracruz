//! Generate Prime Numbers : Remove multiples of 2 or 3
//!
//! ## Context
//!
//! Remove all number that are multiples of 2 or 3
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

    // remove any multiple of 2 or 3
    let filtered_vec: Vec<u32> = num_vec
        .into_iter()
        .filter(|&x| (x % 2 != 0 && x % 3 != 0) || (x == 2 || x == 3))
        .collect::<Vec<_>>();

    let mut content: String = filtered_vec
        .iter()
        .map(|x| x.to_string() + ",")
        .collect();

    content.pop();
    content.push('\n');

    fs::write(FILENAME, content)?;
    
    Ok(())
}

