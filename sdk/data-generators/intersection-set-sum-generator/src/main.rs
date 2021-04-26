//! Data generator sdk/examples/intersection-set-sum
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
use std::{error::Error, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for intersection set sum")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate customer and advertisement-viewer. The former contains a vector of customer identifiers and private values, of the type Vec<(String, f64)>. The latter contains a vector of customer identifiers, of the type Vec<String>. Both are encoded by pinecone.")
        .arg(
            Arg::with_name("file_prefix")
                .short("f")
                .long("file_prefix")
                .value_name("STRING")
                .help("The prefix of data files for the customer and advertisement-viewer.")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("size")
                .short("s")
                .long("size")
                .value_name("NUBMER")
                .help("The size of the customer vector and advertisement-viewer vector.")
                .takes_value(true)
                .validator(is_u64)
                .default_value("1000")
        )
        .arg(
            Arg::with_name("number_of_difference")
                .short("n")
                .long("num_of_diff")
                .value_name("NUBMER")
                .help("The size of the intersection between the customer vector and advertisement-viewer vector.")
                .takes_value(true)
                .validator(is_u64)
                .default_value("250")
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
        .ok_or("Failed to read the file_prefix.")?;
    let row = matches
        .value_of("size")
        .ok_or("Failed to read the size.")?
        .parse::<u64>()
        .map_err(|_| "Failed to parse the size.")?;
    let difference = matches
        .value_of("number_of_difference")
        .ok_or("Failed to read the number of difference.")?
        .parse::<u64>()
        .map_err(|_| "Failed to parse the number of difference.")?;
    let seed = matches
        .value_of("seed")
        .ok_or("Failed to read the seed")?
        .parse::<u64>()
        .map_err(|_| "Cannot parse seed")?;

    let mut rng = StdRng::seed_from_u64(seed);

    let mut customer: Vec<_> = (0..row)
        .map(|n| (format!("{}", n), rng.gen::<f64>() * 1000.0))
        .collect();
    customer.shuffle(&mut rng);

    let encode = pinecone::to_vec(&customer)?;
    let mut file = File::create(format!("{}-customer.dat", file_prefix))?;
    file.write_all(&encode)?;

    // pick `difference` elements from customer and add extra irrelevant elements
    let mut adv: Vec<String> = customer
        .choose_multiple(&mut rng, difference as usize)
        .cloned()
        .map(|(id, _)| id.to_string())
        .collect();
    let mut extra: Vec<String> = (row..(row + row - difference))
        .map(|n| format!("{}", n))
        .collect();
    adv.append(&mut extra);
    adv.shuffle(&mut rng);

    let encode = pinecone::to_vec(&adv)?;
    let mut file = File::create(format!("{}-advertisement-viewer.dat", file_prefix))?;
    file.write_all(&encode)?;

    Ok(())
}

fn is_u64(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}
