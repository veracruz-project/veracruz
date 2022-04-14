//! Prime Numbers Generator : Remove Multiples of 5 or 7
//!
//! ## Context
//!
//! Remove all number that are multiples of 5 or 7
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
    
    // remove all multiples of 5 or 7 
    let filtered_vec: Vec<u32> = num_vec
        .into_iter()
        .filter(|&x| (x % 5 != 0 && x % 7 != 0) || (x == 5 || x == 7))
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

