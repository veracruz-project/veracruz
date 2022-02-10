//! Data generator sdk/rust-examples/postcard-native and postcard-wasm
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright
//!
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
//! and copyright information.
//!
//! # Example
//! ```
//! cargo run -- --file [STRING] --size [VEC_SIZE] --seed [RANDOM_SEED];
//! ```

use clap::{App, Arg};
use rand::{Rng, rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{error::Error, fs, string::String, vec::Vec};

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
    array1: [u16; 7],
    array2: [i32; 13],
    e1: E1,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
enum E2 {
    ENUM1(T2),
    ENUM2([u16; 5]),
    ENUM3(u16),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct T3 {
    e1: E2,
    e2: E2,
    e3: E2,
}

/// Generate a vector of T3 instances
fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for postcard encoding of a vector of T3, a made-up type")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate a vector of T3, a made-up type for profiling the performance on native and wasm programs.")
       .arg(
           Arg::with_name("file")
               .short("f")
               .long("file")
               .value_name("STRING")
               .help("The prefix for the output file")
               .takes_value(true)
               .required(true)
       )
       .arg(
           Arg::with_name("size")
               .short("s")
               .long("size")
               .value_name("NUMBER")
               .help("The number of float-point numbers in each stream")
               .takes_value(true)
               .validator(is_u64)
               .default_value("10")
       )
       .arg(
           Arg::with_name("seed")
               .short("e")
               .long("seed")
               .value_name("NUBMER")
               .help("The seed for the random number generator.")
               .takes_value(true)
               .validator(is_u64)
               .default_value("0"),
        )
        .get_matches();

    let file = matches
        .value_of("file")
        .ok_or("Failed to read the file prefix.")?;
    let size = matches
        .value_of("size")
        .ok_or("Failed to read the size")?
        .parse::<u64>()
        .map_err(|_| "Cannot parse size")?;
    let seed = matches
        .value_of("seed")
        .ok_or("Failed to read the seed")?
        .parse::<u64>()
        .map_err(|_| "Cannot parse seed")?;

    let mut rng = StdRng::seed_from_u64(seed);
    let mut t3_array = Vec::new();
    for _ in 0..size {
        t3_array.push(gen_t3(&mut rng));
    }

    fs::write(file, postcard::to_allocvec(&t3_array)?)?;
    Ok(())
}

/// Generate an instance of T3
fn gen_t3<T: Rng>(rng: &mut T) -> T3 {
    let t1 = T1 {
        f1: rng.gen(),
        f2: rng.gen(),
        f3: rng.gen(),
        i1: rng.gen(),
        i2: rng.gen(),
        i3: rng.gen(),
        c1: rng.gen(),
        c2: rng.gen(),
        c3: rng.gen(),
        e1: E1::ENUM4(String::from("hello rust")),
    };

    let t2 = T2 {
        u1: rng.gen(),
        u2: rng.gen(),
        u3: rng.gen(),
        t1: t1,
        array1: rng.gen(),
        array2: rng.gen(),
        e1: E1::ENUM2(rng.gen()),
    };

    T3 {
        e1: E2::ENUM1(t2),
        e2: E2::ENUM2(rng.gen()),
        e3: E2::ENUM3(rng.gen()),
    }
}

fn is_u64(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}
