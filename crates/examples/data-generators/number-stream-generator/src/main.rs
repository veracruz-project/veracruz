//! Data generator sdk/examples/number-stream-accumulation
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
//! cargo run -- --file_prefix [PREFIX_STRING] --size [VEC_SIZE] --seed [RANDOM_SEED];
//! ```

use clap::Arg;
use rand::{rngs::StdRng, SeedableRng};
use rand_distr::{Distribution, Normal};
use std::{error::Error, fs::File, io::prelude::*};

/// Generate 3 data files: *-init.dat containing a single 64-bit floating point number,
/// and *-1.dat and *-2.dat which are two Vecs of 64-bit floating point numbers respectively.
/// Parameters:
/// * `file_prefix`, String, the prefix of the generated files.
/// * `size`, u64, the size of the Vecs, default is 10.
/// * `seed`, u64, random number seed, default is 0.
fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::Command::new("Data generator for streaming number")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate an initial f64 encoded by postcard and then 2 vectors of streaming data, each of which contains [SIZE] numbers of f64 encoded individually by postcard.")
       .arg(
           Arg::new("file_prefix")
               .short('f')
               .long("file_prefix")
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

    let file_prefix = matches
        .get_one::<String>("file_prefix")
        .expect("Failed to read the file prefix.");
    let dataset_size = *matches
        .get_one::<u64>("size")
        .expect("Failed to read the size");
    let seed = *matches
        .get_one::<u64>("seed")
        .expect("Failed to read the seed");

    let mut rng = StdRng::seed_from_u64(seed);
    let normal = Normal::new(0.0, 50.0)?;
    let init = normal.sample(&mut rng);
    let mut file = File::create(format!("{}-init.txt", file_prefix))?;
    file.write_all(format!("{:?}", init).as_bytes())?;
    let encode = postcard::to_allocvec(&init)?;
    let mut file = File::create(format!("{}-init.dat", file_prefix))?;
    file.write_all(&encode)?;

    for round in 0..dataset_size {
        std::fs::create_dir_all(format!("{}/{}/", file_prefix, round))?;
        let number_1 = normal.sample(&mut rng);
        let number_1 = postcard::to_allocvec(&number_1)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("{0}/{1}/{0}-1.dat", file_prefix, round))?
            .write(&number_1)?;

        let number_2 = normal.sample(&mut rng);
        let number_2 = postcard::to_allocvec(&number_2)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("{0}/{1}/{0}-2.dat", file_prefix, round))?
            .write(&number_2)?;
    }
    Ok(())
}
