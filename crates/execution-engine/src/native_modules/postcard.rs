//! A native module for deserializing Postcard encoding of a vector of a (made-up) customs type
//! and serializing to json string. This is a demonstration to use native module interface.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::Result;
use crate::native_modules::common::StaticNativeModule;
use postcard::from_bytes;
use serde::{Deserialize, Serialize};
use std::fs::write;

pub(crate) struct PostcardService;

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

impl StaticNativeModule for PostcardService {
    fn name(&self) -> &str {
        "Postcard Service"
    }

    fn serve(&mut self, inputs: &[u8]) -> Result<()> {
        let v = from_bytes::<Vec<Struct3>>(inputs)?;
        write(
            "/services/postcard_result.dat",
            serde_json::to_string(&v)?
                .as_bytes()
                .to_vec(),
        )?;
        Ok(())
    }

    /// For the purpose of demonstration, we always return true. In reality,
    /// this function may check validity of the `input`, and even buffer the result
    /// for further uses.
    fn try_parse(&mut self, _input: &[u8]) -> Result<bool> {
        Ok(true)
    }
}

impl PostcardService {
    pub(crate) fn new() -> Self {
        Self {}
    }
}
