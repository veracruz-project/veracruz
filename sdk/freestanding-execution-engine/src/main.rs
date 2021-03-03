//! A freestanding version of the Veracruz execution engine, for offline development.
//!
//! ## About
//!
//! Reads a TOML configuration file at `./config/execution-engine.toml` to ascertain
//! static configuration options for computation.
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

use std::{convert::TryFrom, fmt, fs::File, io::Read, process::exit, time::Instant};
use std::sync::Mutex;
use std::{
    collections::HashMap,
    sync::Arc,
    vec::Vec,
    path::Path,
};

use execution_engine::{
    factory::{single_threaded_execution_engine, ExecutionStrategy},
    hcall::buffer::VFS,
    hcall::common::EngineReturnCode,
};

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
/// The path to the static TOML configuration file that configures
/// freestanding-execution-engine.
const CONFIGURATION_FILE: &'static str = "config/execution-engine.toml";
/// Application version number.
const VERSION: &'static str = "pre-alpha";

/// Name of the field in the TOML file detailing the number of data sources to
/// be expected.
const TOML_DATA_SOURCE_COUNT: &'static str = "data-source-count";
/// Name of the field in the TOML file detailing the maximum call stack size.
/// Not currently enforced!
const TOML_CALL_STACK_SIZE: &'static str = "call-stack-size";

////////////////////////////////////////////////////////////////////////////////////////////////////
// Error codes.
////////////////////////////////////////////////////////////////////////////////////////////////////

/// Return codes returned from the Veracruz entry point, signalling to the
/// Veracruz runtime whether the computation was successful, or not.  (Strictly
/// speaking, the entry point is assumed to return a `Result<(), i32>` value.)
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorCode {
    /// Generic, or underspecified, failure
    Generic,
    /// Failure related to the number of data sources, e.g. an invalid index
    DataSourceCount,
    /// Failure related to the size of data sources, e.g. a buffer size issue
    DataSourceSize,
    /// Failure related to parameters passed to a function, e.g. passing a
    /// negative value where an unsigned value is expected, or similar
    BadInput,
    /// An internal invariant was violated (i.e. we are morally `panicking').
    InvariantFailed,
    /// The required functionality is not yet implemented.
    NotImplemented,
    /// The required platform service is not available on this platform.
    ServiceUnavailable,
}

////////////////////////////////////////////////////////////////////////////////
// Configuration files, and parsing.
////////////////////////////////////////////////////////////////////////////////

/// The static configuration, which in this case fulfills a similar role to the
/// Veracruz policy file.  This contains various important bits of static
/// configuration for a Veracruz computation, such as whether performance
/// statistics should be suppressed, the number of data sources expected, etc.
struct Configuration {
    /// The maximum call stack size of the WASM engine.
    call_stack_size: u32,
    /// The number of data sources expected.
    data_source_count: u32,
}

/// Pretty-printing for `Configuration` types.
impl fmt::Display for Configuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(
            f,
            "{{ call-stack-size: {}, data-source-count: {} }}",
            self.call_stack_size, self.data_source_count
        )
    }
}

/// Reads a `u32` value from the field, `field`, of TOML field, `value`.
/// Defaults to returning `0` if the proposed field is not a field of the TOML
/// file.
fn toml_read_u32(val: &toml::Value, field: &str) -> u32 {
    if let toml::Value::Integer(n) = val[field] {
        let value = u32::try_from(n).unwrap_or_else(|_| 0);
        info!("Read '{}' from field '{}' in TOML file.", value, field);
        value
    } else {
        info!(
            "No field '{}' in TOML file.  Returning '0' as default.",
            field
        );
        0
    }
}

////////////////////////////////////////////////////////////////////////////////
// Command line options and parsing.
////////////////////////////////////////////////////////////////////////////////

/// A struct capturing all of the command line options passed to the program.
struct CommandLineOptions {
    /// The list of file names passed as data-sources.
    data_sources: Vec<String>,
    /// The filename passed as the WASM program to be executed.
    binary: String,
    /// Whether the computation should be timed or not, i.e. should we print
    /// performance statistics for the computation?
    time_computation: bool,
    /// The execution strategy to use when performing the computation.
    execution_strategy: ExecutionStrategy,
}

/// Parses the command line options, building a `CommandLineOptions` struct out
/// of them.  If required options are not present, or if any options are
/// malformed, this will abort the program.
fn parse_command_line(config: &Configuration) -> CommandLineOptions {
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
                .number_of_values(config.data_source_count.into())
                .required(config.data_source_count > 0),
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
            Arg::with_name("time")
                .short("t")
                .long("time")
                .help("Displays performance statistics when set (defaults to false).")
                .required(false)
                .multiple(false),
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
                .multiple(false),
        )
        .get_matches();

    info!("Parsed command line.");

    let execution_strategy: ExecutionStrategy;
    let binary_path: String;
    let mut time: bool = false;
    let mut data_sources_path: Vec<String> = Vec::new();

    if matches.is_present("time") {
        info!("Performance statistics will be collected.");
        time = true
    }

    if let Some(strategy) = matches.value_of("execution-strategy") {
        if strategy == "interp" {
            info!("Selecting interpretation as the execution strategy.");
            execution_strategy = ExecutionStrategy::Interpretation;
        } else if strategy == "jit" {
            info!("Selecting JITting as the execution strategy.");
            execution_strategy = ExecutionStrategy::JIT;
        } else {
            eprintln!("Expecting 'interp' or 'jit' as selectable execution strategies");
            eprintln!(
                "Found '{}' instead passed through '---execution-strategy' flag.",
                strategy
            );
            exit(-1)
        }
    } else {
        info!("Defaulting to 'interp' (WASM interpretation) as the execution strategy");
        execution_strategy = ExecutionStrategy::Interpretation;
    }

    if let Some(binary) = matches.value_of("program") {
        info!("Using '{}' as our WASM executable.", binary);
        binary_path = binary.to_string();
    } else {
        eprintln!("No binary file provided.");
        eprintln!("Please select a WASM file to execute using the '--binary' flag.");
        exit(-1)
    }

    if let Some(data) = matches.values_of("data") {
        let data_sources: Vec<String> = data.map(|e| e.to_string()).collect();

        if data_sources.len() != config.data_source_count as usize {
            eprintln!(
                "Static configuration file states '{}' data sources are expected, but given '{}'.",
                config.data_source_count,
                data_sources.len()
            );
            eprintln!(
                "Please make sure the number of data sources passed with the '--data' flag is \
                 correct."
            );
            exit(-1)
        }

        info!(
            "Selected {} data sources as input to computation.",
            data_sources.len()
        );
        data_sources_path = data_sources;
    } else {
        if config.data_source_count == 0 {
            info!("No data source provided, but configuration indicates this is fine.");
        } else {
            println!(
                "Static configuration file states '{}' data sources are expected, but given '0'.",
                config.data_source_count
            );
            println!(
                "Please make sure the number of data sources passed with the '--data' flag is \
                 correct."
            );
            exit(-1)
        }
    }

    CommandLineOptions {
        data_sources: data_sources_path,
        binary: binary_path,
        execution_strategy: execution_strategy,
        time_computation: time,
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

    (Path::new(file_path).file_name().unwrap().to_str().unwrap().to_string(), contents)
}

/// Reads a static TOML configuration file from a fixed location on disk,
/// returning a `Configuration` struct.  Will abort the program if anything
/// goes wrong.
fn read_configuration_file(fname: &str) -> Configuration {
    info!("Opening configuration file '{}' for reading.", fname);

    let mut file = File::open(fname).unwrap_or_else(|err| {
        eprintln!(
            "Cannot open configuration file '{}'.  Error '{}' returned.",
            fname, err
        );
        exit(-1)
    });

    let mut contents = String::new();

    file.read_to_string(&mut contents).unwrap_or_else(|err| {
        eprintln!(
            "Cannot read configuration file '{}'.  Error '{}' returned.",
            fname, err
        );
        exit(-1)
    });

    info!("Configuration file '{}' read.  Parsing TOML.", fname);

    let toml = toml::from_str(&contents).unwrap_or_else(|err| {
        eprintln!(
            "Cannot parse TOML from file '{}'.  Error '{}' returned.",
            fname, err
        );
        exit(-1)
    });

    info!("TOML file parsed successfully.");

    let call_stack_size = toml_read_u32(&toml, TOML_CALL_STACK_SIZE);
    let data_source_count = toml_read_u32(&toml, TOML_DATA_SOURCE_COUNT);

    Configuration {
        call_stack_size,
        data_source_count,
    }
}


/// Loads the specified data sources, as provided on the command line, for
/// reading and massages them into metadata frames, ready for
/// the computation.  May abort the program if something goes wrong when reading
/// any data source.
fn load_data_sources(cmdline: &CommandLineOptions, vfs : Arc<Mutex<VFS>>) {
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

        // XXX: may panic! if u64 and usize have differing bitwidths...
        let id = u64::try_from(id).unwrap();
        let file_name = format!("input-{}",id);
        vfs.lock().unwrap().write(&file_name,&buffer).unwrap();

        info!("Loading '{}' as file_name '{}' into vfs.", file_path, file_name);
    }
}

/// Entry: reads the static configuration and the command line parameters,
/// parsing both and then starts provisioning the Veracruz host state, before
/// invoking the entry point.
fn main() {
    env_logger::init();

    let config = read_configuration_file(CONFIGURATION_FILE);

    info!("Working with machine configuration: '{}'.", config);

    let cmdline = parse_command_line(&config);

    info!("Command line read successfully.");

    let vfs = Arc::new(Mutex::new(VFS::new(&HashMap::new(),&HashMap::new())));
    let (prog_file_name, program) = load_file(&cmdline.binary);
    vfs.lock().unwrap().write(&prog_file_name,&program).unwrap();
    
    info!("WASM program {} loaded into VFS.", prog_file_name);

    load_data_sources(&cmdline,vfs.clone());

    info!("Data sources loaded.");

    info!("Invoking main.");

    let start = Instant::now();

    match single_threaded_execution_engine(&cmdline.execution_strategy, vfs.clone())
          .unwrap()
          .invoke_entry_point(&prog_file_name) {
        Ok(EngineReturnCode::Success) => {
            if cmdline.time_computation {
                info!("WASM program finished execution in '{:?}.", start.elapsed());
            }
            info!("WASM program executed successfully.");
            info!("Result {:?}.",vfs.lock().unwrap().read("output").unwrap());
        }
        Ok(err_code) => {
            println!(
                "Veracruz program returned error code '{:?}'.",
                err_code
            );
            if cmdline.time_computation {
                println!("WASM program finished execution in '{:?}.", start.elapsed());
            }
        }
        Err(error) => {
            eprintln!("Veracruz program returned unexpected result '{:?}'.", error);
            if cmdline.time_computation {
                println!("WASM program finished execution in '{:?}.", start.elapsed());
            }
            exit(-1)
        }
    }
}
