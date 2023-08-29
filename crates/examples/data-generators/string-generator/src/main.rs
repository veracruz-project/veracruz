//! Data generator sdk/examples/string-edit-distance
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
use std::{error::Error, fs::read_to_string, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::Command::new("Data generator for string")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Convert the [INPUT] txt file to postcard.")
        .arg(
            Arg::new("input_file")
                .short('f')
                .long("input_file")
                .value_name("STRING")
                .help("The input file")
                .num_args(1)
                .required(true),
        )
        .get_matches();

    let input_file = matches
        .get_one::<String>("input_file")
        .expect("Failed to read the input filename.");
    let file_prefix: Vec<&str> = input_file.split('.').collect();
    let file_prefix = file_prefix.first().ok_or("filename error")?;

    let data_string = read_to_string(&input_file)?;

    let encode = postcard::to_allocvec(&data_string)?;

    let mut file = File::create(format!("{}.dat", file_prefix))?;

    file.write_all(&encode)?;

    Ok(())
}
