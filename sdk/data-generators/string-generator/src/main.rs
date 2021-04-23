//! Data generator sdk/examples/string-edit-distance
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
use std::{error::Error, fs::read_to_string, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for string")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Convert the [INPUT] txt file to pinecone.")
        .arg(
            Arg::with_name("input_file")
                .short("f")
                .long("input_file")
                .value_name("STRING")
                .help("The input file")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let input_file = matches
        .value_of("input_file")
        .ok_or("Failed to read the input filename.")?;
    let file_prefix: Vec<&str> = input_file.split('.').collect();
    let file_prefix = file_prefix.first().ok_or("filename error")?;

    let data_string = read_to_string(&input_file)?;

    let encode = pinecone::to_vec(&data_string)?;

    let mut file = File::create(format!("{}.dat", file_prefix))?;

    file.write_all(&encode)?;

    Ok(())
}
