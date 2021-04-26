//! Data generator sdk/examples/private-set-intersection-sum
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use clap::{App, Arg};
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::{error::Error, fs::File, io::prelude::*, path::Path, vec::Vec};

// pinecone does not support u128, so we use two u64 representing the id

type Id = (u64, u64);
type Value = u32;
type Data = Vec<(Id, Value)>;
type Sample = Vec<Id>;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct Input {
    data: Data,
    sample: Sample,
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for privaite set intersection sum")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate a vector of private data comprising 128-bit identifiers and private values,  Vec<((u64, u64), u32)>, and a vector of sample comprising identifiers, Vec<(u64, u64)>. Identifiers are represented by two u64, because pinecone does not support u128.") 
        .arg(
            Arg::with_name("directory")
                .short("d")
                .long("directory")
                .value_name("STRING")
                .help("The output directory")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("size")
                .short("s")
                .long("size")
                .value_name("NUMBER")
                .help("The number of elements in the dataset")
                .takes_value(true)
                .validator(is_u64)
                .default_value("10000")
        )
        .arg(
            Arg::with_name("number_of_sample")
                .short("n")
                .long("num_of_sample")
                .value_name("NUBMER")
                .help("To generate how many samples.")
                .takes_value(true)
                .validator(is_u64)
                .default_value("2500")
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

    let dir = Path::new(
        matches
            .value_of("directory")
            .ok_or("Failed to read the output directory.")?,
    );
    let size = matches
        .value_of("size")
        .ok_or("Failed to read the size.")?
        .parse::<u64>()
        .map_err(|_| "Failed to parse the size.")?;
    let iter = matches
        .value_of("number_of_sample")
        .ok_or("Failed to read the number of samples.")?
        .parse::<u64>()
        .map_err(|_| "Failed to parse the number of samples.")?;
    let seed = matches
        .value_of("seed")
        .ok_or("Failed to read the seed")?
        .parse::<u64>()
        .map_err(|_| "Cannot parse seed")?;

    let seed = seed + ((iter as u64) << 48) + ((size as u64) << 8);

    let mut rng = StdRng::seed_from_u64(seed);

    for i in 0..iter {
        let input = generate(&mut rng, size as usize);
        let bytes = pinecone::to_vec(&input).unwrap();
        let path = dir.join(format!("data-{}-{}.dat", size, i));
        File::create(path)?.write(bytes.as_slice())?;
    }
    Ok(())
}

fn is_u64(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}

fn mk_lame_id(id: u128) -> (u64, u64) {
    ((id >> 64) as u64, (id & ((1 << 64) - 1)) as u64)
}

struct Unique {
    ids: HashSet<u128>,
}

// Could be faster by multiplying `rng.gen()..` modulo 2^128 by a large odd number. What does that
// distribution look like?
impl Unique {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            ids: HashSet::<u128>::with_capacity(capacity),
        }
    }

    fn next(&mut self, rng: &mut impl Rng) -> u128 {
        loop {
            let id = rng.gen();
            if self.ids.insert(id) {
                break id;
            }
        }
    }
}

fn generate(rng: &mut impl Rng, size: usize) -> Input {
    let mut ids = Unique::with_capacity(size);

    let mut data = Vec::with_capacity(size);
    for _ in 0..size {
        data.push((mk_lame_id(ids.next(rng)), rng.gen()));
    }

    let mut sample = Vec::with_capacity(size);
    let intersection = rng.gen_range(0, size);
    for (id, _) in data.iter().take(intersection) {
        sample.push(*id)
    }
    for _ in intersection..size {
        sample.push(mk_lame_id(ids.next(rng)));
    }
    sample.shuffle(rng);

    Input { data, sample }
}
