//! An example to deserialize postcard encoding of a made-up type and serialize to JSON string.
//! This is for comparison to direct use of native module in Veracruz runtime.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.md` in the Veracruz root directory for licensing
//! and copyright information.

use postcard::from_bytes;
use serde::{Deserialize, Serialize};
use std::{fs, vec::Vec};

/// A made-up enum type.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum Enum1 {
    ENUM1_1(u32),
    ENUM1_2(i64),
    ENUM1_3(char),
    ENUM1_4([char; 11]),
}

/// A made-up struct type.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Struct1 {
    f1: f64,
    f2: f64,
    f3: f64,
    i1: i64,
    i2: i64,
    i3: i64,
    c1: char,
    c2: char,
    c3: char,
    e1: Enum1,
}

/// A made-up struct type.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Struct2 {
    u1: u64,
    u2: u64,
    u3: u64,
    t1: Struct1,
    array1: [u16; 7],
    array2: [i32; 13],
    e1: Enum1,
}

/// A made-up enum type.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum Enum2 {
    ENUM2_1(Struct2),
    ENUM2_2([u16; 5]),
    ENUM2_3(u16),
}

/// A made-up struct type.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Struct3 {
    e1: Enum2,
    e2: Enum2,
    e3: Enum2,
}

fn main() -> anyhow::Result<()> {
    let input = fs::read("/input/postcard.dat")?;
    let rst: Vec<Struct3> = from_bytes(&input)?;
    let rst = serde_json::to_string(&rst)?;
    fs::write("/output/postcard_wasm.txt", rst)?;
    Ok(())
}
