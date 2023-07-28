//! Data generator examples/rust-examples/postcard-native and postcard-wasm
//!
//! # Authors
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

use clap::Arg;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{error::Error, fs, vec::Vec};

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

/// Generate a vector of T3 instances
fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::Command::new("Data generator for postcard encoding of a vector of T3, a made-up type")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate a vector of T3, a made-up type for profiling the performance on native and wasm programs.")
       .arg(
           Arg::new("file")
               .short('f')
               .long("file")
               .value_name("STRING")
               .help("The prefix for the output file")
               .num_args(1)
               .required(true)
       )
       .arg(
           Arg::new("size")
               .short('s')
               .long("size")
               .value_name("NUMBER")
               .help("The number of float-point numbers in each stream")
               .num_args(1)
               .value_parser(clap::value_parser!(u64))
               .default_value("10")
       )
       .arg(
           Arg::new("seed")
               .short('e')
               .long("seed")
               .value_name("NUBMER")
               .help("The seed for the random number generator.")
               .num_args(1)
               .value_parser(clap::value_parser!(u64))
               .default_value("0"),
        )
        .get_matches();

    let file = matches
        .get_one::<String>("file")
        .expect("Failed to read the file prefix.");
    let size = *matches
        .get_one::<u64>("size")
        .expect("Failed to read the size.");
    let seed = *matches
        .get_one::<u64>("seed")
        .expect("Failed to read the seed.");

    let mut rng = StdRng::seed_from_u64(seed);
    let mut array = Vec::new();
    for _ in 0..size {
        array.push(gen_struct3(&mut rng));
    }

    fs::write(file, postcard::to_allocvec(&array)?)?;
    Ok(())
}

/// Generate an instance of Struct3
fn gen_struct3<T: Rng>(rng: &mut T) -> Struct3 {
    let t1 = Struct1 {
        f1: rng.gen(),
        f2: rng.gen(),
        f3: rng.gen(),
        i1: rng.gen(),
        i2: rng.gen(),
        i3: rng.gen(),
        c1: rng.gen(),
        c2: rng.gen(),
        c3: rng.gen(),
        e1: gen_enum1(rng),
    };

    let t2 = Struct2 {
        u1: rng.gen(),
        u2: rng.gen(),
        u3: rng.gen(),
        t1: t1,
        array1: rng.gen(),
        array2: rng.gen(),
        e1: gen_enum1(rng),
    };

    Struct3 {
        e1: Enum2::ENUM2_1(t2),
        e2: Enum2::ENUM2_2(rng.gen()),
        e3: Enum2::ENUM2_3(rng.gen()),
    }
}

/// Generate an instance of Enum1
fn gen_enum1<T: Rng>(rng: &mut T) -> Enum1 {
    let type_idx = rng.gen_range(0..4);
    match type_idx {
        0 => Enum1::ENUM1_1(rng.gen()),
        1 => Enum1::ENUM1_2(rng.gen()),
        2 => Enum1::ENUM1_3(rng.gen()),
        3 => Enum1::ENUM1_4(rng.gen()),
        _other => panic!("Should not reach here"),
    }
}
