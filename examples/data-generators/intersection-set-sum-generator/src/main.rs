//! Data generator sdk/examples/intersection-set-sum
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
use std::{error::Error, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::Command::new("Data generator for intersection set sum")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate customer and advertisement-viewer. The former contains a vector of customer identifiers and private values, of the type Vec<(String, f64)>. The latter contains a vector of customer identifiers, of the type Vec<String>. Both are encoded by postcard.")
        .arg(
            Arg::new("file_prefix")
                .short('f')
                .long("file_prefix")
                .value_name("STRING")
                .help("The prefix of data files for the customer and advertisement-viewer.")
                .num_args(1)
                .required(true)
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_name("NUBMER")
                .help("The size of the customer vector and advertisement-viewer vector.")
                .num_args(1)
                .value_parser(clap::value_parser!(u64))
                .default_value("1000")
        )
        .arg(
            Arg::new("number_of_difference")
                .short('n')
                .long("num_of_diff")
                .value_name("NUBMER")
                .help("The size of the intersection between the customer vector and advertisement-viewer vector.")
                .num_args(1)
                .value_parser(clap::value_parser!(u64))
                .default_value("250")
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
    let row = *matches
        .get_one::<u64>("size")
        .expect("Failed to read the size.");
    let difference = *matches
        .get_one::<u64>("number_of_difference")
        .expect("Failed to read the number of difference.");
    let seed = *matches
        .get_one::<u64>("seed")
        .expect("Failed to read the seed.");

    let mut rng = StdRng::seed_from_u64(seed);

    let mut customer: Vec<_> = (0..row)
        .map(|n| (format!("{}", n), rng.gen::<f64>() * 1000.0))
        .collect();
    customer.shuffle(&mut rng);

    let encode = postcard::to_allocvec(&customer)?;
    let mut file = File::create(format!("{}-customer.dat", file_prefix))?;
    file.write_all(&encode)?;

    // pick `difference` elements from customer and add extra irrelevant elements
    let mut adv: Vec<String> = customer
        .choose_multiple(&mut rng, difference as usize)
        .cloned()
        .map(|(id, _)| id)
        .collect();
    let mut extra: Vec<String> = (row..(row + row - difference))
        .map(|n| format!("{}", n))
        .collect();
    adv.append(&mut extra);
    adv.shuffle(&mut rng);

    let encode = postcard::to_allocvec(&adv)?;
    let mut file = File::create(format!("{}-advertisement-viewer.dat", file_prefix))?;
    file.write_all(&encode)?;

    Ok(())
}
