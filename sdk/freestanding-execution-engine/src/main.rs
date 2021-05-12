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

use clap::{App, Arg};
use execution_engine::{execute, fs::FileSystem};
use log::*;
use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
    vec::Vec,
};
use veracruz_utils::policy::principal::{ExecutionStrategy, Principal};
use wasi_types::Rights;

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
fn parse_command_line() -> Result<CommandLineOptions, Box<dyn Error>> {
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

    let execution_strategy = if let Some(strategy) = matches.value_of("execution-strategy") {
        if strategy == "interp" {
            info!("Selecting interpretation as the execution strategy.");
            ExecutionStrategy::Interpretation
        } else if strategy == "jit" {
            info!("Selecting JITting as the execution strategy.");
            ExecutionStrategy::JIT
        } else {
            return Err(format!(
                "Expecting 'interp' or 'jit' as selectable execution strategies, but found {}",
                strategy
            )
            .into());
        }
    } else {
        return Err("Default 'interp' value is not loaded correctly".into());
    };

    let binary = if let Some(binary) = matches.value_of("program") {
        info!("Using '{}' as our WASM executable.", binary);
        binary.to_string()
    } else {
        return Err("No binary file provided.".into());
    };
    let data_sources = if let Some(data) = matches.values_of("data") {
        let data_sources: Vec<String> = data.map(|e| e.to_string()).collect();
        info!(
            "Selected {} data sources as input to computation.",
            data_sources.len()
        );
        data_sources
    } else {
        Vec::new()
    };

    Ok(CommandLineOptions {
        data_sources,
        binary,
        execution_strategy,
    })
}

/// Reads a WASM file from disk (actually, will read any file, but we only need
/// it for WASM here) and return a collection of bytes corresponding to that
/// file.  Will abort the program if anything goes wrong.
fn load_file(file_path: &str) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    info!("Opening file '{}' for reading.", file_path);

    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();

    file.read_to_end(&mut contents)?;

    Ok((
        Path::new(file_path)
            .file_name()
            .ok_or(format!("Failed to obtain file name on {}", file_path))?
            .to_str()
            .ok_or(format!(
                "Failed to convert file name to string on {}",
                file_path
            ))?
            .to_string(),
        contents,
    ))
}

/// Loads the specified data sources, as provided on the command line, for
/// reading and massages them into metadata frames, ready for
/// the computation.  May abort the program if something goes wrong when reading
/// any data source.
fn load_data_sources(
    cmdline: &CommandLineOptions, vfs: Arc<Mutex<FileSystem>>,
) -> Result<(), Box<dyn Error>> {
    for (id, file_path) in cmdline.data_sources.iter().enumerate() {
        info!(
            "Loading data source '{}' with id {} for reading.",
            file_path, id
        );
        let mut file = File::open(file_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        vfs.lock()
            .map_err(|e| format!("Failed to lock vfs, error: {:?}", e))?
            .write_file_by_filename(&Principal::InternalSuperUser, &file_path, &buffer, false)?;

        info!("Loading '{}' into vfs.", file_path);
    }
    Ok(())
}

/// Entry: reads the static configuration and the command line parameters,
/// parsing both and then starts provisioning the Veracruz host state, before
/// invoking the entry point.
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let cmdline = parse_command_line()?;
    info!("Command line read successfully.");

    let (prog_file_name, program) = load_file(&cmdline.binary)?;

    let mut right_table = HashMap::new();
    let mut file_table = HashMap::new();
    let read_right = Rights::PATH_OPEN | Rights::FD_READ | Rights::FD_SEEK;
    let write_right = Rights::PATH_OPEN
        | Rights::FD_WRITE
        | Rights::FD_SEEK
        | Rights::PATH_CREATE_FILE
        | Rights::PATH_FILESTAT_SET_SIZE;

    // Manually create the Right table for the VFS.
    file_table.insert(prog_file_name.to_string(), write_right);
    for file_path in cmdline.data_sources.iter() {
        file_table.insert(file_path.to_string(), read_right);
    }
    file_table.insert(OUTPUT_FILE.to_string(), write_right);
    right_table.insert(Principal::Program(prog_file_name.to_string()), file_table);

    let vfs = Arc::new(Mutex::new(FileSystem::new(right_table)));
    vfs.lock()
        .map_err(|e| format!("Failed to lock vfs, error: {:?}", e))?
        .write_file_by_filename(
            &Principal::InternalSuperUser,
            &prog_file_name,
            &program,
            false,
        )?;
    info!("WASM program {} loaded into VFS.", prog_file_name);

    load_data_sources(&cmdline, vfs.clone())?;
    info!("Data sources loaded.");

    info!("Invoking main.");
    let main_time = Instant::now();
    let return_code = execute(&cmdline.execution_strategy, vfs.clone(), &prog_file_name)?;
    info!("return code: {:?}", return_code);
    info!("time: {} micro seconds", main_time.elapsed().as_micros());
    Ok(())
}
