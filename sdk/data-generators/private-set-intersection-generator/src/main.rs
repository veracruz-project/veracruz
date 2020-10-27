//! Data generator sdk/examples/private-set-intersection
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
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::{error::Error, fs::File, io::prelude::*};

/// The format of the contents of the input sets, encoding meta-data about an employee.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
struct Person {
    /// Name of the employee
    name: String,
    /// Internal ID of the employee
    employee_id: String,
    /// Age of the employee
    age: u8,
    /// Grade of the employee
    grade: u8,
}

fn read_csv(filename: &str) -> Result<Vec<csv::StringRecord>, Box<dyn Error>> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b',')
        .has_headers(true)
        .from_path(filename)?;

    let mut buffer = Vec::new();

    for result in reader.records() {
        buffer.push(result?);
    }
    Ok(buffer)
}

fn extract_columns(entries: &Vec<csv::StringRecord>) -> Result<HashSet<Person>, Box<dyn Error>> {
    let mut buffer = HashSet::new();

    for entry in entries.iter() {
        let name = entry.get(0).unwrap().to_string();
        let employee_id = entry.get(1).unwrap().to_string();
        let age = entry.get(2).unwrap().parse::<u8>().unwrap();
        let grade = entry.get(3).unwrap().parse::<u8>().unwrap();
        buffer.insert(Person {
            name,
            employee_id,
            age,
            grade,
        });
    }

    Ok(buffer)
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for private set intersection")
        .version("pre-alpha")
        .author("The Veracruz Development Team, Arm Research")
        .about("Convert the [INPUT] csv file to pinecone. Each entry in the file comprises name (String), employee_id (String), age (u8), and grade (u8).") 
        .arg(
            Arg::with_name("input_file")
                .short("f")
                .long("input_file")
                .value_name("STRING")
                .help("The input file")
                .takes_value(true)
                .required(true)
        )
        .get_matches();

    let input_file = matches
        .value_of("input_file")
        .ok_or("Failed to read the input filename.")?;
    let file_prefix: Vec<&str> = input_file.split('.').collect();
    let file_prefix = file_prefix.first().ok_or("filename error")?;

    let records = read_csv(input_file)?;
    let columns = extract_columns(&records)?;
    let encode = pinecone::to_vec(&columns)?;
    let mut file = File::create(format!("{}.dat", file_prefix))?;
    file.write_all(&encode)?;

    Ok(())
}
