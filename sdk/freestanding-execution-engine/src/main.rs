//! A freestanding version of the Veracruz execution engine, for offline development.
//!
//! ## About
//!
//! The WASM binary to execute, and any data sources being passed to the binary,
//! are passed with the `--binary` and `--data` flags, respectively.  A
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
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use std::{
    collections::HashMap,
    sync::Arc,
    vec::Vec,
    path::Path,
    sync::Mutex,
    fs::File, io::Read, process::exit, time::Instant
};

use execution_engine::{
    factory::execute,
    fs::FileSystem,
};
use wasi_types::Rights;
use veracruz_utils::policy::principal::{ExecutionStrategy, Principal};
use clap::{App, Arg};
use log::*;

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// About freestanding-execution-engine/Veracruz.
const ABOUT: &'static str = "Veracruz: a platform for practical secure multi-party \
                             computations.\nThis is freestanding-execution-engine, an offline \
                             counterpart of the Veracruz execution engine that is part of the \
                             Veracruz platform.  This can be used to test and develop WASM \
                             programs before deployment on the platform.";
/// The name of the application.
const APPLICATION_NAME: &'static str = "freestanding-execution-engine";
/// The authors list.
const AUTHORS: &'static str = "The Veracruz Development Team.  See the file `AUTHORS.markdown` in \
                               the Veracruz root directory for detailed authorship information.";
/// Application version number.
const VERSION: &'static str = "pre-alpha";
/// Application version number.
const OUTPUT_FILE: &'static str = "output";

////////////////////////////////////////////////////////////////////////////////
// Command line options and parsing.
////////////////////////////////////////////////////////////////////////////////

/// A struct capturing all of the command line options passed to the program.
struct CommandLineOptions {
    /// The list of file names passed as data-sources.
    data_sources: Vec<String>,
    /// The filename passed as the WASM program to be executed.
    binary: String,
    /// The execution strategy to use when performing the computation.
    execution_strategy: ExecutionStrategy,
}

/// Parses the command line options, building a `CommandLineOptions` struct out
/// of them.  If required options are not present, or if any options are
/// malformed, this will abort the program.
fn parse_command_line() -> CommandLineOptions {
    let matches = App::new(APPLICATION_NAME)
        .version(VERSION)
        .author(AUTHORS)
        .about(ABOUT)
        .arg(
            Arg::with_name("data")
                .short("d")
                .long("data")
                .value_name("FILES")
                .help("Space-separated paths to the data source files on disk.")
                .multiple(true),
        )
        .arg(
            Arg::with_name("program")
                .short("p")
                .long("program")
                .value_name("FILE")
                .help("Path to the WASM binary on disk.")
                .multiple(false)
                .required(true),
        )
        .arg(
            Arg::with_name("execution-strategy")
                .short("x")
                .long("execution-strategy")
                .value_name("interp | jit")
                .help(
                    "Selects the execution strategy to use: interpretation or JIT (defaults to \
                     interpretation).",
                )
                .required(false)
                .multiple(false)
                .default_value("interp"),
        )
        .get_matches();

    info!("Parsed command line.");

    let execution_strategy = 
    if let Some(strategy) = matches.value_of("execution-strategy") {
        if strategy == "interp" {
            info!("Selecting interpretation as the execution strategy.");
            ExecutionStrategy::Interpretation
        } else if strategy == "jit" {
            info!("Selecting JITting as the execution strategy.");
            ExecutionStrategy::JIT
        } else {
            eprintln!("Expecting 'interp' or 'jit' as selectable execution strategies");
            eprintln!(
                "Found '{}' instead passed through '---execution-strategy' flag.",
                strategy
            );
            exit(-1)
        }
    } else {
        info!("Default 'interp' value is not loaded correctly");
        exit(-1)
    };

    let binary = 
        if let Some(binary) = matches.value_of("program") {
        info!("Using '{}' as our WASM executable.", binary);
        binary.to_string()
    } else {
        eprintln!("No binary file provided.");
        eprintln!("Please select a WASM file to execute using the '--binary' flag.");
        exit(-1)
    };
    let data_sources = 
    if let Some(data) = matches.values_of("data") {
        let data_sources: Vec<String> = data.map(|e| e.to_string()).collect();
        info!(
            "Selected {} data sources as input to computation.",
            data_sources.len()
        );
        data_sources
    } else {
        Vec::new()
    };

    CommandLineOptions {
        data_sources,
        binary,
        execution_strategy,
    }
}

/// Reads a WASM file from disk (actually, will read any file, but we only need
/// it for WASM here) and return a collection of bytes corresponding to that
/// file.  Will abort the program if anything goes wrong.
fn load_file(file_path: &str) -> (String, Vec<u8>) {
    info!("Opening file '{}' for reading.", file_path);

    let mut file = File::open(file_path).unwrap_or_else(|err| {
        eprintln!(
            "Cannot open WASM binary '{}'.  Error '{}' returned.",
            file_path, err
        );
        exit(-1)
    });

    let mut contents = Vec::new();

    file.read_to_end(&mut contents).unwrap_or_else(|err| {
        eprintln!(
            "Cannot read WASM binary '{}' to completion.  Error '{}' returned.",
            file_path, err
        );
        exit(-1);
    });

    (Path::new(file_path).file_name().expect(&format!("Failed to extract file name from path {}", file_path)).to_str().expect(&format!("Failed to convert the filename in path {}", file_path)).to_string(), contents)
}

/// Loads the specified data sources, as provided on the command line, for
/// reading and massages them into metadata frames, ready for
/// the computation.  May abort the program if something goes wrong when reading
/// any data source.
fn load_data_sources(cmdline: &CommandLineOptions, vfs: Arc<Mutex<FileSystem>>) {
    for (id, file_path) in cmdline.data_sources.iter().enumerate() {
        info!("Loading data source '{}' with id {} for reading.", file_path, id);

        let mut file = File::open(file_path).unwrap_or_else(|err| {
            eprintln!(
                "Could not open data source '{}'.  Error '{}' returned.",
                file_path, err
            );
            exit(-1)
        });

        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer).unwrap_or_else(|err| {
            error!(
                "Could not read data source '{}'.  Error '{}' returned.",
                file_path, err
            );
            exit(-1)
        });

        vfs.lock()
            .expect("Failed to lock vfs")
            .write_file_by_filename(&Principal::InternalSuperUser, &file_path, &buffer, false)
            .unwrap_or_else(|err| {
                eprintln!(
                    "Could not write data source '{}'.  Error '{}' returned.",
                    file_path, err
                );
                exit(-1)
            });

        info!( "Loading '{}' into vfs.", file_path);
    }
}

/// Entry: reads the static configuration and the command line parameters,
/// parsing both and then starts provisioning the Veracruz host state, before
/// invoking the entry point.
fn main() {
    env_logger::init();
    let cmdline = parse_command_line();
    info!("Command line read successfully.");

    let (prog_file_name, program) = load_file(&cmdline.binary);

    let mut right_table = HashMap::new();
    let mut file_table = HashMap::new();
    let read_right = Rights::PATH_OPEN | Rights::FD_READ | Rights::FD_SEEK;
    let write_right = Rights::PATH_OPEN | Rights::FD_WRITE | Rights::FD_SEEK;

    // Manually create the Right table for the VFS.
    for file_path in cmdline.data_sources.iter() {
        file_table.insert(file_path.to_string(), read_right);
    }
    file_table.insert(OUTPUT_FILE.to_string(), write_right);
    // TODO remove
    file_table.insert("output.txt".to_string(), write_right);
    right_table.insert(Principal::Program(prog_file_name.to_string()), file_table);

    let vfs = Arc::new(Mutex::new(FileSystem::new(right_table)));
    // Write the program twice on purpose, 
    // to check if `write_file_by_filename` overwrite the file correctly.
    vfs.lock()
        .expect("Failed to lock the vfs")
        .write_file_by_filename(&Principal::InternalSuperUser, &prog_file_name, &program, false)
        .expect(&format!("Failed to write to file {}", prog_file_name));
    vfs.lock()
        .expect("Failed to lock the vfs")
        .write_file_by_filename(&Principal::InternalSuperUser, &prog_file_name, &program, false)
        .expect(&format!("Failed to write to file {}", prog_file_name));
    info!("WASM program {} loaded into VFS.", prog_file_name);

    load_data_sources(&cmdline, vfs.clone());
    info!("Data sources loaded.");

    info!("Invoking main.");
    let main_time = Instant::now();
    execute(&cmdline.execution_strategy, vfs.clone(), &prog_file_name).expect(&format!("failed to execute {}", prog_file_name));
    info!("time: {} micro seconds", main_time.elapsed().as_micros())
}
