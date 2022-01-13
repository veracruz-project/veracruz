use std::fs;
use std::string::String;
use std::vec::Vec;
use std::time::Instant;
use pinecone::from_bytes;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
enum E1 {
    ENUM1(u32),
    ENUM2(i64),
    ENUM3(char),
    ENUM4(String),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct T1 {
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
struct T2 {
    u1: u64,
    u2: u64,
    u3: u64,
    t1: T1,
    array1: [u16;7],
    array2: [i32;13],
    e1: E1,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
enum E2 {
    ENUM1(T2),
    ENUM2([u16;5]),
    ENUM3(u16),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct T3 {
    e1: E2,
    e2: E2,
    e3: E2,
}

fn main() -> anyhow::Result<()>  {
    let input = fs::read("/input/pinecone_string.dat")?;
    let now = Instant::now();
    let rst : Vec<T3> = from_bytes(&input)?;
    let rst = serde_json::to_string(&rst)?;
    fs::write("/output/pinecone_wasm.txt", rst)?;
    println!("time: {} ms", now.elapsed().as_micros());
    Ok(())
}
