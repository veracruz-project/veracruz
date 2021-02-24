//! Data generator sdk/examples/number-stream-accumulation
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.
//! 
//! # Example
//! ```
//! cargo run -- --file_prefix [PREFIX_STRING] --size [VEC_SIZE] --seed [RANDOM_SEED]; 
//! ```

use clap::{App, Arg};
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
    let matches = App::new("Data generator for streaming number")
        .version("pre-alpha")
        .author("The Veracruz Development Team, Arm Research")
        .about("Generate an initial f64 encoded by pinecone and then 2 vectors of streaming data, each of which contains [SIZE] numbers of f64 encoded individually by pinecone.") 
       .arg(
           Arg::with_name("file_prefix")
               .short("f")
               .long("file_prefix")
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

    let file_prefix = matches
        .value_of("file_prefix")
        .ok_or("Failed to read the file prefix.")?;
    let dataset_size = matches
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
    let normal = Normal::new(0.0, 50.0)?;
    let init = normal.sample(&mut rng);
    let mut file = File::create(format!("{}-init.txt", file_prefix))?;
    file.write_all(format!("{:?}", init).as_bytes())?;
    let encode = pinecone::to_vec(&init)?;
    let mut file = File::create(format!("{}-init.dat", file_prefix))?;
    file.write_all(&encode)?;

    let dataset1_txt: Vec<f64> = (0..dataset_size).map(|_| normal.sample(&mut rng)).collect();
    let dataset1: Vec<Vec<u8>> = dataset1_txt
        .iter()
        .map(|n| pinecone::to_vec(&n).unwrap())
        .collect();
    let encode = pinecone::to_vec(&dataset1)?;

    let mut file = File::create(format!("{}-1.txt", file_prefix))?;
    file.write_all(format!("{:?}\n{:?}", dataset1_txt, dataset1).as_bytes())?;
    let mut file = File::create(format!("{}-1.dat", file_prefix))?;
    file.write_all(&encode)?;

    let dataset2_txt: Vec<f64> = (0..dataset_size).map(|_| normal.sample(&mut rng)).collect();
    let dataset2: Vec<Vec<u8>> = dataset2_txt
        .iter()
        .map(|n| pinecone::to_vec(&n).unwrap())
        .collect();
    let encode = pinecone::to_vec(&dataset2)?;

    let mut file = File::create(format!("{}-2.txt", file_prefix))?;
    file.write_all(format!("{:?}\n{:?}", dataset2_txt, dataset2).as_bytes())?;
    let mut file = File::create(format!("{}-2.dat", file_prefix))?;
    file.write_all(&encode)?;

    Ok(())
}

fn is_u64(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}
