//! Echo
//!
//! ## Context
//!
//! Read from 'input.txt', encode then using pinecone and write to 'output'.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::fs;
use anyhow;

/// Read from 'input.txt', encode then using pinecone and write to 'output'.
fn main() -> anyhow::Result<()> {
    let input = "/input.txt";
    let output = "/output";

    let mut input_string = fs::read(input)?;

    println!("hello");
    fs::create_dir_all("/a/b/c/d")?;
    fs::write("/a/b/c/d/e.txt","hello")?;

    input_string.append(&mut "read_dir on ROOT:\"".as_bytes().to_vec());
    for file in fs::read_dir("/")? {
        input_string.append(&mut file?.path().to_str().unwrap().as_bytes().to_vec())
    }
    input_string.append(&mut "\"read_dir on '/a':".as_bytes().to_vec());
    for file in fs::read_dir("/a")? {
        input_string.append(&mut file?.path().to_str().unwrap().as_bytes().to_vec())
    }
    input_string.append(&mut "\"read_dir on '/a/b':".as_bytes().to_vec());
    for file in fs::read_dir("/a/b")? {
        input_string.append(&mut file?.path().to_str().unwrap().as_bytes().to_vec())
    }
    input_string.append(&mut "\"read_dir on '/a/b/c':".as_bytes().to_vec());
    for file in fs::read_dir("/a/b/c")? {
        input_string.append(&mut file?.path().to_str().unwrap().as_bytes().to_vec())
    }
    input_string.append(&mut "\"read_dir on '/a/b/c/d':".as_bytes().to_vec());
    for file in fs::read_dir("/a/b/c/d")? {
        input_string.append(&mut file?.path().to_str().unwrap().as_bytes().to_vec())
    }
    input_string.append(&mut "\"".as_bytes().to_vec());

    let rst = pinecone::to_vec(&input_string)?;
    fs::write(output, rst)?;
    Ok(())
}
