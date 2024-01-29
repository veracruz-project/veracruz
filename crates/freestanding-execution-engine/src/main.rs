//! A freestanding version of the Veracruz execution engine, for offline development.
//!
//! ## About
//!
//! The WASM binary to execute, and any data sources being passed to the binary,
//! are passed with the `--program-binary` and `--data` flags, respectively.  A
//! runtime error is raised if the number of input data sources does not match
//! the number specified in the configuration TOML.
//!
//! To see verbose output of what is happening, set `RUST_LOG=info` before
//! executing.
//!
//! On success, the return value of the WASM program's `main` function, and the
//! result that the program wrote back to Veracruz host, will be printed to
//! stdout.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.md` in the Veracruz root directory for licensing
//! and copyright information.

use clap::Parser;
use execution_engine::{execute, Environment};
use log::*;
use policy_utils::{
    parsers::parse_pipeline,
    pipeline::Expr, 
    principal::{FilePermissions, ExecutionStrategy, Service, ServiceSource},
};
use std::{
    collections::HashMap,
    error::Error,
    path::PathBuf,
    time::Instant,
    vec::Vec,
};
use anyhow::{anyhow, Result};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// About freestanding-execution-engine/Veracruz.
const ABOUT: &str = "Veracruz: a platform for practical secure multi-party computations.\nThis is \
                     freestanding-execution-engine, an offline counterpart of the Veracruz \
                     execution engine that is part of the Veracruz platform.  This can be used to \
                     test and develop WASM programs before deployment on the platform.";
/// The name of the application.
const APPLICATION_NAME: &str = "freestanding-execution-engine";
/// The authors list.
const AUTHORS: &str = "The Veracruz Development Team.  See the file `AUTHORS.md` in the \
                       Veracruz `docs` subdirectory for detailed authorship information.";
/// Application version number.
const VERSION: &str = "alpha";

////////////////////////////////////////////////////////////////////////////////
// Command line options and parsing.
////////////////////////////////////////////////////////////////////////////////

/// A struct capturing all of the command line options passed to the program.
#[derive(Debug, Parser)]
#[command(name = APPLICATION_NAME, author = AUTHORS, version = VERSION, about = ABOUT, long_about = None, rename_all = "kebab-case")]
struct CommandLineOptions {
    /// The list of file names passed as input data-sources.
    #[arg(short = 'i', long, value_name = "PATH")]
    input_source: Vec<String>,
    /// The execution strategy to use when performing the computation.
    #[arg(long, short = 'e', value_name = "Interpretation | JIT", default_value = "JIT")]
    execution_strategy: ExecutionStrategy,
    /// Environment variables for the program.
    #[arg(long, value_name = "PATH", value_parser=env_parser)]
    env: Vec<(String, String)>,
    #[arg(long, value_name = "SERVICE => DIR", value_parser = service_parser)]
    service: Vec<Service>,
    #[arg(short = 'r', long, value_name = "PATH", value_parser=pipeline_parser)]
    pipeline: Box<Expr>,
}

fn service_parser(input: &str) -> Result<Service> {
    match input.splitn(2,"=>").collect::<Vec<_>>().as_slice() {
        [source, dir] => {
            // TODO distinguish internal and provisional
            Ok(Service::new(ServiceSource::Internal(source.trim().to_string()), PathBuf::from(dir.trim())))
        }
        _ => Err(anyhow!("Error in parsing service"))
    }
}

fn env_parser(input: &str) -> Result<(String, String)> {
    match input.splitn(2,"=").collect::<Vec<_>>().as_slice() {
        [var, value] => {
            // TODO distinguish internal and provisional
            Ok((var.to_string(), value.to_string()))
        }
        _ => Err(anyhow!("Error in parsing environment variables"))
    }
}

fn pipeline_parser(input: &str) -> Result<Box<Expr>> {
    parse_pipeline(input)
}

/// Entry: reads the static configuration and the command line parameters,
/// parsing both and then starts provisioning the Veracruz host state, before
/// invoking the entry point.
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let cmdline = CommandLineOptions::parse();
    info!("Command line read successfully.");

    let permission = cmdline.input_source.iter().map(|s| (PathBuf::from(s), FilePermissions{read: true, write: true, execute: true})).collect::<HashMap<_, _>>();

    info!("Data sources loaded.");

    // Execute the pipeline with the supplied environment
    let env = Environment {
        environment_variables: cmdline.env,
        ..Default::default()
    };

    info!(
        "Invoking pipeline {:?} with environment {:?}.",
        cmdline.pipeline, env
    );

    let main_time = Instant::now();

    let return_code = execute(
        &cmdline.execution_strategy,
        &permission,
        &permission,
        &cmdline.service,
        cmdline.pipeline.clone(),
        &env,
    )?;

    info!(
        "Return code of pipeline '{:?}' execution is: {:?}",
        cmdline.pipeline, return_code
    );

    info!(
        "Time to compute pipeline '{:?}': {} micro seconds",
        cmdline.pipeline,
        main_time.elapsed().as_micros()
    );

    Ok(())
}
