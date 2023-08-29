//! Data generator for sdk/examples/linear-regression
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
use rand::{prelude::*, rngs::StdRng, SeedableRng};
use rand_distr::{Distribution, Normal};
use std::{env, error::Error, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::Command::new("Data generator for linear regression")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate a vec of points, Vec<(f64,f64)>, and encode it by postcard.")
        .arg(
            Arg::new("file_name")
                .short('f')
                .long("file_name")
                .value_name("STRING")
                .help("The filename of the generated data.")
                .num_args(1)
                .default_value("linear-regression"),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_name("NUBMER")
                .help("The number of points.")
                .num_args(1)
                .value_parser(clap::value_parser!(u64))
                .required(true),
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
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err("Insufficient parameters".into());
    }

    // read in all arguments
    let file_name = matches
        .get_one::<String>("file_name")
        .expect("Failed to read the filename.");
    let size = *matches
        .get_one::<u64>("size")
        .expect("Failed to read the size.");
    let seed = *matches
        .get_one::<u64>("seed")
        .expect("Failed to read the seed.");

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

    let encode = postcard::to_allocvec(&dataset).unwrap();
    let mut file = File::create(format!("{}.dat", file_name))?;
    file.write_all(&encode)?;
    Ok(())
}
