//! Data generator sdk/examples/private-set-intersection-sum
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright
//!
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use clap::Arg;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::{error::Error, fs, io::Write, path::Path, vec::Vec};

// postcard does not support u128, so we use two u64 representing the id

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
    let matches = clap::Command::new("Data generator for privaite set intersection sum")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate a vector of private data comprising 128-bit identifiers and private values,  Vec<((u64, u64), u32)>, and a vector of sample comprising identifiers, Vec<(u64, u64)>. Identifiers are represented by two u64, because postcard does not support u128.")
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("STRING")
                .help("The output directory")
                .num_args(1)
                .required(true)
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_name("NUMBER")
                .help("The number of elements in the dataset")
                .num_args(1)
                .value_parser(clap::value_parser!(u64))
                .default_value("10000")
        )
        .arg(
            Arg::new("number_of_sample")
                .short('n')
                .long("num_of_sample")
                .value_name("NUBMER")
                .help("To generate how many samples.")
                .num_args(1)
                .value_parser(clap::value_parser!(u64))
                .default_value("2500")
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

    let directory = matches
        .get_one::<String>("directory")
        .expect("Failed to read the output directory.");
    let size = *matches
        .get_one::<u64>("size")
        .expect("Failed to read the size.");
    let iter = *matches
        .get_one::<u64>("number_of_sample")
        .expect("Failed to read the number of samples.");
    let seed = *matches
        .get_one::<u64>("seed")
        .expect("Failed to read the seed.");

    let dir = Path::new(directory);
    let seed = seed + ((iter as u64) << 48) + ((size as u64) << 8);

    let mut rng = StdRng::seed_from_u64(seed);

    for i in 0..iter {
        let (data, sample) = generate(&mut rng, size as usize);
        let data = postcard::to_allocvec(&data).map_err(|e| {
            eprintln!("Cannot encode {:?} in postcard", data);
            e
        })?;
        let sample = postcard::to_allocvec(&sample).map_err(|e| {
            eprintln!("Cannot encode {:?} in postcard", sample);
            e
        })?;
        let path = dir.join(format!("data-{}-{}", size, i));
        fs::create_dir_all(&path)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.join("data.dat"))?
            .write(data.as_slice())?;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.join("sample.dat"))?
            .write(sample.as_slice())?;
    }
    Ok(())
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

fn generate(rng: &mut impl Rng, size: usize) -> (Data, Sample) {
    let mut ids = Unique::with_capacity(size);

    let mut data = Vec::with_capacity(size);
    for _ in 0..size {
        data.push((mk_lame_id(ids.next(rng)), rng.gen()));
    }

    let mut sample = Vec::with_capacity(size);
    let intersection = rng.gen_range(0..size);
    for (id, _) in data.iter().take(intersection) {
        sample.push(*id)
    }
    for _ in intersection..size {
        sample.push(mk_lame_id(ids.next(rng)));
    }
    sample.shuffle(rng);

    (data, sample)
}
