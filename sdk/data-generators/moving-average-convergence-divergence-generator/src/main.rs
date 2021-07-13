//! Data generator sdk/examples/moving-average-convergence-divergence
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright
//!
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use clap::{App, Arg};
use rand::{prelude::*, rngs::StdRng, SeedableRng};
use rand_distr::{Distribution, Normal};
use std::{error::Error, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for moving average convergence divergence algorithm")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate a vector of f64. In `generate` mode, it generates random data. In `external` mode, it reads the first [SIZE] numbers from an external data source.") 
        // Command for generate random data
        .subcommand(
            App::new("generate")
               .about("Generate random data.")
               .version("pre-alpha")
               .author("The Veracruz Development Team")
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
                       .help("The number of float-point numbers")
                       .takes_value(true)
                       .validator(is_u64)
                       .default_value("1000")
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
        )
        // Command for generate data from external resource.
        .subcommand(
            App::new("external")
               .about("Read from an external input file.")
               .version("pre-alpha")
               .author("The Veracruz Development Team")
               .arg(
                   Arg::with_name("input_file")
                       .short("i")
                       .long("input_file")
                       .value_name("STRING")
                       .help("The data source")
                       .takes_value(true)
                       .required(true)
               )
               .arg(
                   Arg::with_name("size")
                       .short("s")
                       .long("size")
                       .value_name("NUMBER")
                       .help("The number of float-point numbers")
                       .takes_value(true)
                       .validator(is_u64)
                       .default_value("1000")
               )
        )
        .get_matches();

    let (file_prefix, size, dataset) = match matches.subcommand() {
        ("external", Some(sub_args)) => {
            let input_file = sub_args
                .value_of("input_file")
                .ok_or("Failed to read the input filename.")?;
            let size = sub_args
                .value_of("size")
                .ok_or("Failed to read the size.")?
                .parse::<u64>()
                .map_err(|_| "Failed to parse the size.")?;

            let file_prefix: Vec<&str> = input_file.split('.').collect();
            let file_prefix = file_prefix.first().ok_or("filename error")?;

            let mut reader = csv::ReaderBuilder::new()
                .delimiter(b',')
                .has_headers(false)
                .from_path(input_file.clone())?;

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
        ("generate", Some(sub_args)) => {
            let file_prefix = sub_args
                .value_of("file_prefix")
                .ok_or("Failed to read the prefix name of the output file.")?;
            let size = sub_args
                .value_of("size")
                .ok_or("Failed to read the size.")?
                .parse::<u64>()
                .map_err(|_| "Failed to parse the size.")?;
            let seed = sub_args
                .value_of("seed")
                .ok_or("Failed to read the seed")?
                .parse::<u64>()
                .map_err(|_| "Cannot parse seed")?;

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

    let encode = pinecone::to_vec(dataset.split_at(size as usize).0)?;
    let mut file = File::create(format!("{}-{}.dat", file_prefix, size))?;
    file.write_all(&encode)?;
    Ok(())
}

fn is_u64(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}
