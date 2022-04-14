//! Prime Numbers Generator : Remove all non-prime numbers
//!
//! ## Context
//!
//! Remove all non-prime numbers from the number-set
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use std::{fs, usize};
use anyhow;

const FILENAME: &'static str = "/output/number-set.txt"; 

fn main() -> anyhow::Result<()>{

    let content = String::from_utf8(fs::read(FILENAME)?)?;

    let mut num_vec: Vec<u32> = content
        .trim()
        .split(",")
        .map(|x| x.parse::<u32>().unwrap())
        .collect();

    sieve_of_eratosthenes(&mut num_vec)?;
        
    let mut content: String = num_vec 
        .iter()
        .map(|x| x.to_string() + ",")
        .collect();
   
    // remove last comma, add end of line character
    content.pop();
    content.push('\n');

    fs::write(FILENAME, content)?;
    
    Ok(())
}

// implements sieve_of_eratosthenes algorithm, and retain only prime numbers from nums
fn sieve_of_eratosthenes(nums: &mut Vec<u32>) -> anyhow::Result<()> {
    let n = (nums[nums.len() - 1] + 1) as usize;
    let mut is_prime = vec![true; n];

    let mut p: usize = 2;

    while p * p <= n {
        if is_prime[p] {
            let mut i = p * 2;
            while i < n {
                is_prime[i] = false;
                i += p;
            } 
        }
        p += 1;
    }

    // exclude 0 and 1 
    is_prime[0] = false;
    is_prime[1] = false;

    nums.retain(|&x| is_prime[x as usize]);

    Ok(())
}
