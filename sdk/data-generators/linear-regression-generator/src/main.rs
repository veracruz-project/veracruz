//! Data generator for sdk/examples/linear-regression
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
use rand::{prelude::*, rngs::StdRng, SeedableRng};
use rand_distr::{Distribution, Normal};
use std::{env, error::Error, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for linear regression")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate a vec of points, Vec<(f64,f64)>, and encode it by pinecone.")
        .arg(
            Arg::with_name("file_name")
                .short("f")
                .long("file_name")
                .value_name("STRING")
                .help("The filename of the generated data.")
                .takes_value(true)
                .default_value("linear-regression"),
        )
        .arg(
            Arg::with_name("size")
                .short("s")
                .long("size")
                .value_name("NUBMER")
                .help("The number of points.")
                .takes_value(true)
                .validator(is_u64)
                .required(true),
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
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err("Insufficient parameters".into());
    }

    // read in all arguments
    let file_name = matches
        .value_of("file_name")
        .ok_or("Failed to read the filename")?;
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
    let normal = Normal::new(0.0, 0.005).map_err(|_| "Failed to generate a normal distribution")?;
    let gradient: f64 = rng.gen();

    let dataset: Vec<_> = (0..size)
        .map(|_| {
            // rng.gen() generate floating-number between 0 and 1
            let x_val: f64 = rng.gen::<f64>() * 1000.0;
            let y_val = (gradient + normal.sample(&mut rng)) * x_val;
            (x_val, y_val)
        })
        .collect();

    let mut file = File::create(format!("{}.txt", file_name))?;
    file.write_all(format!("{:?}", dataset).as_bytes())?;

    let encode = pinecone::to_vec(&dataset).unwrap();
    let mut file = File::create(format!("{}.dat", file_name))?;
    file.write_all(&encode)?;
    Ok(())
}

fn is_u64(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}
