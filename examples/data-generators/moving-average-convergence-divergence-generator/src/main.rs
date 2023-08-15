//! Data generator sdk/examples/moving-average-convergence-divergence
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
use std::{error::Error, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::Command::new("Data generator for moving average convergence divergence algorithm")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate a vector of f64. In `generate` mode, it generates random data. In `external` mode, it reads the first [SIZE] numbers from an external data source.")
        // Command for generate random data
        .subcommand(
            clap::Command::new("generate")
               .about("Generate random data.")
               .version("pre-alpha")
               .author("The Veracruz Development Team")
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
                       .help("The number of float-point numbers")
                       .num_args(1)
                       .value_parser(clap::value_parser!(u64))
                       .default_value("1000")
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
        )
        // Command for generate data from external resource.
        .subcommand(
            clap::Command::new("external")
               .about("Read from an external input file.")
               .version("pre-alpha")
               .author("The Veracruz Development Team")
               .arg(
                   Arg::new("input_file")
                       .short('i')
                       .long("input_file")
                       .value_name("STRING")
                       .help("The data source")
                       .num_args(1)
                       .required(true)
               )
               .arg(
                   Arg::new("size")
                       .short('s')
                       .long("size")
                       .value_name("NUMBER")
                       .help("The number of float-point numbers")
                       .num_args(1)
                       .value_parser(clap::value_parser!(u64))
                       .default_value("1000")
               )
        )
        .get_matches();

    let (file_prefix, size, dataset) = match matches.subcommand() {
        Some(("external", sub_args)) => {
            let input_file = sub_args
                .get_one::<String>("input_file")
                .expect("Failed to read the input filename.");
            let size = *sub_args
                .get_one::<u64>("size")
                .expect("Failed to read the size");

            let file_prefix: Vec<&str> = input_file.split('.').collect();
            let file_prefix = file_prefix.first().ok_or("filename error")?;

            let mut reader = csv::ReaderBuilder::new()
                .delimiter(b',')
                .has_headers(false)
                .from_path(input_file)?;

            let mut dataset = Vec::new();
            for record in reader.records() {
                let record = record?;
                let cell = record
                    .get(0)
                    .ok_or("csv record out of range")?
                    .parse::<f64>()?;
                dataset.push(cell);
            }
            (file_prefix.to_string(), size, dataset)
        }
        Some(("generate", sub_args)) => {
            let file_prefix = sub_args
                .get_one::<String>("file_prefix")
                .expect("Failed to read the prefix name of the output file.");
            let size = *sub_args
                .get_one::<u64>("size")
                .expect("Failed to read the size");
            let seed = *sub_args
                .get_one::<u64>("seed")
                .expect("Failed to read the seed");

            let mut rng = StdRng::seed_from_u64(seed);
            let normal =
                Normal::new(0.0, 2.0).map_err(|_| "Failed to generate a normal distribution")?;
            let dataset = (0..size).fold(Vec::new(), |mut acc, _| {
                let last = acc.last().cloned().unwrap_or(rng.gen::<f64>() * 100.0);
                acc.push(last + normal.sample(&mut rng));
                acc
            });
            (file_prefix.to_string(), size, dataset)
        }
        _ => {
            return Err("Please choose mode: (1) `external` for existing data source, (2) `generate` for generate data".into());
        }
    };

    let encode = postcard::to_allocvec(dataset.split_at(size as usize).0)?;
    let mut file = File::create(format!("{}-{}.dat", file_prefix, size))?;
    file.write_all(&encode)?;
    Ok(())
}
