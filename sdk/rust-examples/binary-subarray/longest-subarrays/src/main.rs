//! Longest Subarrays
//!
//! ## Context
//!
//! Reads user input, and then find the:-
//! 1. Longest Alternating Subarray
//! 2. Longest Zero Subarray
//! 3. Longest One Subaray
//! And then prints the output.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use anyhow;
use std::{fs, process};

const FILENAME: &'static str = "/output/output.txt";

fn main() -> anyhow::Result<()> {
    let file_vec: Vec<u8> = fs::read(FILENAME)?;
    let content: String = String::from_utf8_lossy(&file_vec).to_string();

    if content.len() < 1 {
        process::exit(1);
    }

    let alter_string_ends: (usize, usize) = longest_alternating_subarray(&content);
    let zero_string_ends: (usize, usize) = longest_zero_subarray(&content);
    let one_string_ends: (usize, usize) = longest_one_subarray(&content);

    let mut ret = String::new();

    let start: usize = alter_string_ends.0;
    let end: usize = alter_string_ends.1 - alter_string_ends.0;
    let alter_string: &str = &content[start..end];

    let start: usize = zero_string_ends.0;
    let end: usize = zero_string_ends.1 - zero_string_ends.0;
    let mut zero_string: &str = &content[start..end];

    let start: usize = one_string_ends.0;
    let end: usize = one_string_ends.1 - one_string_ends.0;
    let mut one_string: &str = &content[start..end];

    if zero_string == "" {
        if content.len() != one_string.len() {
            zero_string = "0";
        }
    }

    if one_string == "" {
        if content.len() != zero_string.len() {
            one_string = "1";
        }
    }

    ret.push_str(alter_string);
    ret.push_str("\n");
    ret.push_str(zero_string);
    ret.push_str("\n");
    ret.push_str(one_string);
    ret.push_str("\n");

    fs::write(FILENAME, ret)?;

    Ok(())
}

fn longest_alternating_subarray(s: &String) -> (usize, usize) {
    let bytes: &[u8] = s.as_bytes();

    let mut start: usize = 0;
    let mut res: usize = 1;
    let mut temp: usize = 1;

    for (i, &item) in bytes.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if (item == b'1' && bytes[i - 1] == b'0') || (item == b'0' && bytes[i - 1] == b'1') {
            temp += 1;
        } else {
            if res < temp {
                res = temp;
                start = i - res;
            } else {
                temp = 1;
            }
        }
    }

    if res < temp {
        res = temp;
        start = s.len() - res;
    }

    if res == 1 {
        return (0, 0);
    }
    (start, start + res)
}

fn longest_zero_subarray(s: &String) -> (usize, usize) {
    let bytes: &[u8] = s.as_bytes();

    let mut start: usize = 0;
    let mut res: usize = 1;
    let mut temp: usize = 1;

    for (i, &item) in bytes.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if item == b'0' && bytes[i - 1] == b'0' {
            temp += 1;
        } else {
            if res < temp {
                res = temp;
                start = i - res;
            } else {
                temp = 1;
            }
        }
    }

    if res < temp {
        res = temp;
        start = s.len() - res;
    }

    if res == 1 {
        return (0, 0);
    }

    (start, start + res)
}

fn longest_one_subarray(s: &String) -> (usize, usize) {
    let bytes: &[u8] = s.as_bytes();

    let mut start: usize = 0;
    let mut res: usize = 1;
    let mut temp: usize = 1;

    for (i, &item) in bytes.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if item == b'1' && bytes[i - 1] == b'1' {
            temp += 1;
        } else {
            if res < temp {
                res = temp;
                start = i - res;
            } else {
                temp = 1;
            }
        }
    }

    if res < temp {
        res = temp;
        start = s.len() - res;
    }

    if res == 1 {
        return (0, 0);
    }

    (start, start + res)
}
