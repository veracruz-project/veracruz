//! Data generator for sdk/examples/idash2017-logistic-regression
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
use std::{error::Error, fs::File, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for logistic regression")
        .version("pre-alpha")
        .author("The Veracruz Development Team, Arm Research")
        .about("Generate datasets for logistic regression. Each dataset contains a training set with the configuration and a testing set. In `generate` mode, it generates random raw data and then datasets. In `external` mode, it generates datasets from an external data source.")
        // common configuration for all subcommand
        .arg(
            Arg::with_name("fold")
                .short("o")
                .long("fold")
                .value_name("NUBMER")
                .help("Divide the data into several folds, one of which is the testing set and the rest are the training set. This parameter also determines the number of datasets.")
                .takes_value(true)
                .validator(is_u64)
                .default_value("5"),
        )
        .arg(
            Arg::with_name("number_of_iteration")
                .short("n")
                .long("num_of_iter")
                .value_name("NUBMER")
                .help("The number of interation in the training.")
                .takes_value(true)
                .validator(is_u64)
                .default_value("7")
        )
        .arg(
            Arg::with_name("sigmoid")
                .short("g")
                .long("sigmoid")
                .value_name("NUBMER")
                .help("The degree of sigmoid in the training.")
                .takes_value(true)
                .validator(is_3_5_7)
                .default_value("5")
        )
        .arg(
            Arg::with_name("gamma_up")
                .short("u")
                .long("gamma_up")
                .value_name("NUBMER")
                .help("Gamma up.")
                .takes_value(true)
                .validator(is_i64)
                .default_value("1")
        )
        .arg(
            Arg::with_name("gamma_down")
                .short("d")
                .long("gamma_down")
                .value_name("NUBMER")
                .help("Gamma down.")
                .takes_value(true)
                .validator(is_i64)
                .default_value("-1")
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
        // Command for generate random data
        .subcommand(
            App::new("generate")
               .about("Generate random raw data and shuffle it into [FOLD] datasets. Each dataset contains pinecone encode of a training set with the configuration and a testing set.")
               .version("pre-alpha")
               .author("The Veracruz Development Team, Arm Research")
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
                   Arg::with_name("row")
                       .short("r")
                       .long("row")
                       .value_name("NUMBER")
                       .help("The number of rows, or entries, in the generated raw data")
                       .takes_value(true)
                       .validator(is_u64)
                       .default_value("20000")
               )
               .arg(
                   Arg::with_name("column")
                       .short("c")
                       .long("column")
                       .value_name("NUMBER")
                       .help("The number of column, or dimension, in the generated raw data")
                       .takes_value(true)
                       .validator(is_u64)
                       .default_value("20")
               )
        )
        // Command for generate data from external resource.
        .subcommand(
            App::new("external")
               .about("Generate [FOLD] dataset from external resource. Each dataset contains pinecone encode of a training set with the configuration and a testing set.")
               .version("pre-alpha")
               .author("The Veracruz Development Team, Arm Research")
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
                   Arg::with_name("is_label_first")
                       .short("l")
                       .long("is_label_first")
                       .value_name("BOOLEAN")
                       .help("If the label is the first column (true) or the last (false)")
                       .takes_value(true)
                       .validator(is_bool)
                       .default_value("false")
               )
        )
        .get_matches();

    let fold = matches
        .value_of("fold")
        .ok_or("Failed to read the number of fold.")?
        .parse::<u64>()
        .map_err(|_| "Failed to parse the number of fold.")?;
    let num_of_iter = matches
        .value_of("number_of_iteration")
        .ok_or("Failed to read the number of interation.")?
        .parse::<u64>()
        .map_err(|_| "Failed to parse the number of interation.")?;
    let degree_of_sigmoid = matches
        .value_of("sigmoid")
        .ok_or("Failed to read the degree of sigmoid.")?
        .parse::<u64>()
        .map_err(|_| "Failed to parse the degree of sigmoid.")?;
    let gamma_up = matches
        .value_of("gamma_up")
        .ok_or("Failed to read the gamma-up value.")?
        .parse::<i64>()
        .map_err(|_| "Failed to parse the gamma-up value.")?;
    let gamma_down = matches
        .value_of("gamma_up")
        .ok_or("Failed to read the gamma-down value.")?
        .parse::<i64>()
        .map_err(|_| "Failed to parse the gamma-down value.")?;
    let seed = matches
        .value_of("seed")
        .ok_or("Failed to read the seed")?
        .parse::<u64>()
        .map_err(|_| "Cannot parse seed")?;

    let mut rng = StdRng::seed_from_u64(seed);

    // Read the data or generate data depending on the subcommand
    let (file_prefix, header, mut dataset) = match matches.subcommand() {
        ("generate", Some(sub_args)) => {
            let file_prefix = sub_args
                .value_of("file_prefix")
                .ok_or("Failed to read the prefix name of the output file.")?;
            let row = sub_args
                .value_of("row")
                .ok_or("Failed to read the number of rows.")?
                .parse::<u64>()
                .map_err(|_| "Failed to parse the number of rows.")?;
            let column = sub_args
                .value_of("column")
                .ok_or("Failed to read the number of columns.")?
                .parse::<u64>()
                .map_err(|_| "Failed to parse the number of columns.")?;

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
            header[0] = format!("Y");
            (file_prefix.to_string(), header, dataset)
        }
        ("external", Some(sub_args)) => {
            let is_y_first = sub_args
                .value_of("is_label_first")
                .ok_or("Failed to read the value of is-label-first.")?
                .parse::<bool>()
                .map_err(|_| "Failed to parse the value of is-label-first.")?;
            let input_file = sub_args
                .value_of("input_file")
                .ok_or("Failed to read the input filename.")?;
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
        let encode = pinecone::to_vec(&(
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

fn is_u64(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}

fn is_i64(v: String) -> Result<(), String> {
    match v.parse::<i64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to i64, with error {:?}", v, e)),
    }
}

fn is_3_5_7(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(o) => {
            if o == 3 || o == 5 || o == 7 {
                Ok(())
            } else {
                Err(format!("Value {} must be 3, 5or 7", o))
            }
        }
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}

fn is_bool(v: String) -> Result<(), String> {
    match v.parse::<bool>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to bool, with error {:?}", v, e)),
    }
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
        // put the `y` at begining and covert it to 1.0 and -1.0
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

fn write_csv(filename: &str, header: &[String], dataset: &Dataset) -> Result<(), Box<dyn Error>> {
    let mut wtr = csv::WriterBuilder::new().from_path(filename)?;
    wtr.serialize(header)?;
    for data in dataset.iter() {
        wtr.serialize(data)?;
    }
    Ok(())
}
