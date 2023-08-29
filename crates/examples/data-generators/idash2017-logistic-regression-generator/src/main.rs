//! Data generator for sdk/examples/idash2017-logistic-regression
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
    let matches = clap::Command::new("Data generator for logistic regression")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Generate datasets for logistic regression. Each dataset contains a training set with the configuration and a testing set. In `generate` mode, it generates random raw data and then datasets. In `external` mode, it generates datasets from an external data source.")
        // common configuration for all subcommand
        .arg(
            Arg::new("fold")
                .short('o')
                .long("fold")
                .value_name("NUBMER")
                .help("Divide the data into several folds, one of which is the testing set and the rest are the training set. This parameter also determines the number of datasets.")
                .num_args(1)
                .value_parser(clap::value_parser!(u64))
                .default_value("5"),
        )
        .arg(
            Arg::new("number_of_iteration")
                .short('n')
                .long("num_of_iter")
                .value_name("NUBMER")
                .help("The number of interation in the training.")
                .num_args(1)
                .value_parser(clap::value_parser!(u64))
                .default_value("7")
        )
        .arg(
            Arg::new("sigmoid")
                .short('g')
                .long("sigmoid")
                .value_name("NUBMER")
                .help("The degree of sigmoid in the training.")
                .num_args(1)
                .value_parser(["3", "5", "7"])
                .default_value("5")
        )
        .arg(
            Arg::new("gamma_up")
                .short('u')
                .long("gamma_up")
                .value_name("NUBMER")
                .help("Gamma up.")
                .num_args(1)
                .value_parser(clap::value_parser!(i64))
                .default_value("1")
        )
        .arg(
            Arg::new("gamma_down")
                .short('d')
                .long("gamma_down")
                .value_name("NUBMER")
                .help("Gamma down.")
                .num_args(1)
                .value_parser(clap::value_parser!(i64))
                .default_value("-1")
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
        // Command for generate random data
        .subcommand(
            clap::Command::new("generate")
               .about("Generate random raw data and shuffle it into [FOLD] datasets. Each dataset contains postcard encode of a training set with the configuration and a testing set.")
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
                   Arg::new("row")
                       .short('r')
                       .long("row")
                       .value_name("NUMBER")
                       .help("The number of rows, or entries, in the generated raw data")
                       .num_args(1)
                       .value_parser(clap::value_parser!(u64))
                       .default_value("20000")
               )
               .arg(
                   Arg::new("column")
                       .short('c')
                       .long("column")
                       .value_name("NUMBER")
                       .help("The number of column, or dimension, in the generated raw data")
                       .num_args(1)
                       .value_parser(clap::value_parser!(u64))
                       .default_value("20")
               )
        )
        // Command for generate data from external resource.
        .subcommand(
            clap::Command::new("external")
               .about("Generate [FOLD] dataset from external resource. Each dataset contains postcard encode of a training set with the configuration and a testing set.")
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
                   Arg::new("is_label_first")
                       .short('l')
                       .long("is_label_first")
                       .value_name("BOOLEAN")
                       .help("If the label is the first column (true) or the last (false)")
                       .num_args(1)
                       .value_parser(clap::value_parser!(bool))
                       .default_value("false")
               )
        )
        .get_matches();

    let fold = *matches
        .get_one::<u64>("fold")
        .expect("Failed to read the number of fold.");
    let num_of_iter = *matches
        .get_one::<u64>("number_of_iteration")
        .expect("Failed to read the number of interation.");
    let s: String = matches
        .get_one::<String>("sigmoid")
        .expect("Failed to read the degree of sigmoid.")
        .to_string();
    let degree_of_sigmoid: u64 = s.parse::<u64>()?;
    let gamma_up = *matches
        .get_one::<i64>("gamma_up")
        .expect("Failed to read the gamma-up value.");
    let gamma_down = *matches
        .get_one::<i64>("gamma_down")
        .expect("Failed to read the gamma-down value.");
    let seed = *matches
        .get_one::<u64>("seed")
        .expect("Failed to read the seed.");

    let mut rng = StdRng::seed_from_u64(seed);

    // Read the data or generate data depending on the subcommand
    let (file_prefix, header, mut dataset) = match matches.subcommand() {
        Some(("generate", sub_args)) => {
            let file_prefix = sub_args
                .get_one::<String>("file_prefix")
                .expect("Failed to read the prefix name of the output file.");
            let row = *sub_args
                .get_one::<u64>("row")
                .expect("Failed to read the number of rows.");
            let column = *sub_args
                .get_one::<u64>("column")
                .expect("Failed to read the number of columns.");

            let normal =
                Normal::new(0.0, 100.0).map_err(|_| "Failed to generate a normal distribution")?;
            let dataset: Vec<_> = (0..row)
                .map(|_| {
                    // Generate a list of f64
                    let mut entry: Vec<f64> =
                        (0..column + 1).map(|_| normal.sample(&mut rng)).collect();
                    // Convert the first value as Y, which should be either 1.0 or -1.0
                    entry[0] = if entry[0] >= 0.0 { 1.0 } else { -1.0 };
                    entry
                })
                .collect();
            let mut header: Vec<String> = (0..column + 1).map(|n| format!("Col{}", n)).collect();
            header[0] = String::from("Y");
            (file_prefix.to_string(), header, dataset)
        }
        Some(("external", sub_args)) => {
            let is_y_first = *sub_args
                .get_one::<bool>("is_label_first")
                .expect("Failed to read the value of is-label-first.");
            let input_file = sub_args
                .get_one::<String>("input_file")
                .expect("Failed to read the input filename.");
            let file_prefix: Vec<&str> = input_file.split('.').collect();
            let file_prefix = file_prefix.first().ok_or("filename error")?;
            let (header, dataset) = read_csv(&input_file, is_y_first)?;
            (file_prefix.to_string(), header, dataset)
        }
        _ => return Err("Must choose either `generate` or `external`.".into()),
    };

    let amount = dataset.len() / fold as usize;

    for fold_item in 0..fold {
        let (test_set, train_set) = dataset.partial_shuffle(&mut rng, amount);
        write_csv(
            &format!("{}-test-{}.csv", file_prefix, fold_item),
            &header,
            &test_set.to_vec(),
        )?;
        write_csv(
            &format!("{}-train-{}.csv", file_prefix, fold_item),
            &header,
            &train_set.to_vec(),
        )?;
        let encode = postcard::to_allocvec(&(
            train_set,
            test_set,
            num_of_iter,
            degree_of_sigmoid,
            gamma_up,
            gamma_down,
        ))?;
        let mut file = File::create(format!("{}-data-{}.dat", file_prefix, fold_item))?;
        file.write_all(&encode)?;
    }

    Ok(())
}

type Dataset = Vec<Vec<f64>>;

/// IO
fn read_csv(filename: &str, is_y_first: bool) -> Result<(Vec<String>, Dataset), Box<dyn Error>> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(b',')
        .has_headers(true)
        .from_path(filename)?;
    let header = reader.headers()?;
    let mut header = header.iter().fold(Vec::new(), |mut acc, s| {
        acc.push(s.to_string());
        acc
    });

    if !is_y_first {
        let pop: String = header.pop().ok_or("No element in headers")?;
        header.insert(0, pop);
    }

    println!("{:?}", header);

    let mut rst = Vec::new();
    for record in reader.records() {
        let record = record?;
        // put the `y` at beginning and covert it to 1.0 and -1.0
        let y_index = if is_y_first { 0 } else { record.len() - 1 };
        let y = match record
            .get(y_index)
            .ok_or("csv record out of range")?
            .parse::<u32>()?
        {
            1 => 1.0,
            0 => -1.0,
            _ => return Err("y value must be either 1 for true or 0 for false".into()),
        };
        let mut row = vec![y];
        let range = if is_y_first {
            1..record.len()
        } else {
            0..record.len() - 1
        };
        for i in range {
            let cell = record
                .get(i)
                .ok_or("csv record out of range")?
                .parse::<f64>()?;
            row.push(cell * y);
        }
        rst.push(row);
    }
    Ok((header, rst))
}

fn write_csv(
    filename: &str,
    header: &[String],
    dataset: &[Vec<f64>],
) -> Result<(), Box<dyn Error>> {
    let mut wtr = csv::WriterBuilder::new().from_path(filename)?;
    wtr.serialize(header)?;
    for data in dataset.iter() {
        wtr.serialize(data)?;
    }
    Ok(())
}
