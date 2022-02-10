use crate::fs::{Service, FileSystem, FileSystemResult};
use wasi_types::ErrNo;
use std::string::String;
use serde::{Deserialize, Serialize};
use postcard::from_bytes;

pub(crate) struct PostcardService;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum E1 {
    ENUM1(u32),
    ENUM2(i64),
    ENUM3(char),
    ENUM4(String),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct T1 {
    f1: f64,
    f2: f64,
    f3: f64,
    i1: i64,
    i2: i64,
    i3: i64,
    c1: char,
    c2: char,
    c3: char,
    e1: E1,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct T2 {
    u1: u64,
    u2: u64,
    u3: u64,
    t1: T1,
    array1: [u16;7],
    array2: [i32;13],
    e1: E1,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum E2 {
    ENUM1(T2),
    ENUM2([u16;5]),
    ENUM3(u16),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct T3 {
    e1: E2,
    e2: E2,
    e3: E2,
}

impl Service for PostcardService {
    fn name(&self) -> &str {
        "Postcard Service"
    }

    fn serve(&self, fs: &mut FileSystem, inputs: &[u8]) -> FileSystemResult<()> {
        let v = from_bytes::<Vec<T3>>(inputs).map_err(|_| ErrNo::Inval)?;
        fs.write_file_by_absolute_path("/services/postcard_result.dat", serde_json::to_string(&v).map_err(|_| ErrNo::Inval)?.as_bytes().to_vec(), false)?;
        Ok(())
    }

    fn try_parse(&self, _input: &[u8]) -> FileSystemResult<bool> {
        Ok(true)
    }
}

impl PostcardService {
    pub(crate) fn new() -> Self {
        Self{}
    }
}
