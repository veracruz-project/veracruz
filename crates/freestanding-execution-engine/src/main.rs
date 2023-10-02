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

use anyhow::anyhow;
use clap::{App, Arg};
use execution_engine::{execute, Environment};
use log::*;
use policy_utils::{
    parsers::parse_pipeline,
    pipeline::Expr, 
    principal::{FilePermissions, ExecutionStrategy, NativeModule, NativeModuleType},
};
use std::{
    collections::HashMap,
    error::Error,
    path::PathBuf,
    time::Instant,
    vec::Vec,
    iter::FromIterator,
};

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
struct CommandLineOptions {
    /// The list of file names passed as input data-sources.
    input_sources: Vec<String>,
    ///// The list of file names passed as output.
    //output_sources: Vec<String>,
    /// The execution strategy to use when performing the computation.
    execution_strategy: ExecutionStrategy,
    ///// Whether the contents of `stdout` should be dumped before exiting.
    //dump_stdout: bool,
    ///// Whether the contents of `stderr` should be dumped before exiting.
    //dump_stderr: bool,
    ///// Whether clock functions (`clock_getres()`, `clock_gettime()`) should be
    ///// enabled.
    //enable_clock: bool,
    /// Environment variables for the program.
    environment_variables: Vec<(String, String)>,
    ///// Whether strace is enabled.
    //enable_strace: bool,
    /// A list of native module names.
    native_modules_names: Vec<String>,
    /// A list of paths to native module entry points.
    native_modules_entry_points: Vec<PathBuf>,
    /// A list of paths to native module special files.
    native_modules_special_files: Vec<PathBuf>,
    /// The conditional pipeline of programs to execute.
    pipeline: Box<Expr>,
}

/// Parses the command line options, building a `CommandLineOptions` struct out
/// of them.  If required options are not present, or if any options are
/// malformed, this will abort the program.
fn parse_command_line() -> Result<CommandLineOptions, Box<dyn Error>> {
    let matches = clap::Command::new(APPLICATION_NAME)
        .version(VERSION)
        .author(AUTHORS)
        .about(ABOUT)
        .arg(
            Arg::new("input")
                .short('i')
                .long("input-source")
                .value_name("DIRECTORIES")
                .help(
                    "Space-separated paths to the input directories on disk. The directories are \
                     copied into the root directory in Veracruz space. All programs are granted \
                     with read capabilities.",
                )
                .num_args(0..),
        )
        //.arg(
            //Arg::with_name("output")
                //.short("o")
                //.long("output-source")
                //.value_name("DIRECTORIES")
                //.help(
                    //"Space-separated paths to the output directories. The directories are copied \
                     //into disk on the host. All program are granted with write capabilities.",
                //)
                //.multiple(true),
        //)
        .arg(
            Arg::new("native-module-name")
                .long("native-module-name")
                .value_name("NAME")
                .help("Specifies the name of the native module to use for the computation. \
This must be of the form \"--native-module-name name\". Multiple --native-module-name flags may be provided.")
                .num_args(1)
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("native-module-entry-point")
                .long("native-module-entry-point")
                .value_name("FILE")
                .help("Specifies the path to the entry point of the native module to use for the computation. \
This must be of the form \"--native-module-entry-point path\". Multiple --native-module-entry-point flags may be provided. \
If the value is an empty string, the native module is assumed to be static, i.e. part of the Veracruz runtime, \
and is looked up by name in the static native modules table.")
                .num_args(1)
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("native-module-special-file")
                .long("native-module-special-file")
                .value_name("FILE")
                .help("Specifies the path to the special file of the native module to use for the computation. \
This must be of the form \"--native-module-special-file path\". Multiple --native-module-special-file flags may be provided.")
                .num_args(1)
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("pipeline")
                .short('r')
                .long("pipeline")
                .value_name("PIPELINE")
                .help("The conditional pipeline of programs to be executed.")
                .required(true),
        )
        .arg(
            Arg::new("execution-strategy")
                .short('x')
                .long("execution-strategy")
                .value_name("interp | jit")
                .default_value("jit")
                .help(
                    "Selects the execution strategy to use: interpretation or JIT (defaults to \
                     interpretation).",
                ),
        )
        //.arg(
            //Arg::with_name("dump-stdout")
                //.short("d")
                //.long("dump-stdout")
                //.help("Whether the contents of stdout should be dumped before exiting"),
        //)
        //.arg(
            //Arg::with_name("dump-stderr")
                //.short("e")
                //.long("dump-stderr")
                //.help("Whether the contents of stderr should be dumped before exiting"),
        //)
        //.arg(
            //Arg::with_name("enable-clock")
                //.short("c")
                //.long("enable-clock")
                //.help(
                    //"Whether clock functions (`clock_getres()`, `clock_gettime()`) should be \
                     //enabled.",
                //),
        //)
        .arg(
            Arg::new("env")
                .long("env")
                .help("Specify an environment variable and value (VAR=VAL).")
                .value_name("VAR=VAL")
                .num_args(1)
                .action(ArgAction::Append),
        )
        //.arg(
            //Arg::with_name("strace")
                //.long("strace")
                //.help("Enable strace-like output for WASI calls."),
        //)
        .get_matches();

    info!("Parsed command line.");

    let execution_strategy = {
        let strategy = matches
            .get_one::<String>("execution-strategy")
            .ok_or("jit")?
            .as_str();

        match strategy {
            "interp" => {
                info!("Selecting interpretation as the execution strategy.");
                ExecutionStrategy::Interpretation
            }
            "jit" => {
                info!("Selecting JITting as the execution strategy.");
                ExecutionStrategy::JIT
            }
            _ => {
                return Err(format!(
                    "Expecting 'interp' or 'jit' as selectable execution strategies, but found {}",
                    strategy
                )
                .into());
            }
        }
    };

    // Read all native module names
    let native_modules_names = matches
        .get_many::<String>("native-module-name")
        .map_or(Vec::new(), |p| p.map(|s| s.to_string()).collect::<Vec<_>>());

    // Read all native module entry points
    let native_modules_entry_points = matches
        .get_many::<String>("native-module-entry-point")
        .map_or(Vec::new(), |p| {
            p.map(|s| PathBuf::from(s)).collect::<Vec<_>>()
        });

    // Read all native module special files
    let native_modules_special_files = matches
        .get_many::<String>("native-module-special-file")
        .map_or(Vec::new(), |p| {
            p.map(|s| PathBuf::from(s)).collect::<Vec<_>>()
        });

    let pipeline = if let Some(pipeline_string) = matches.get_one::<String>("pipeline") {
        parse_pipeline(pipeline_string)?
    } else {
        return Err("No executable pipeline provided".into());
    };

    let input_sources = if let Some(data) = matches.get_many::<String>("input") {
        let input_sources: Vec<String> = data.map(|e| e.to_string()).collect();
        info!(
            "Selected {} data sources as input to computation.",
            input_sources.len()
        );
        input_sources
    } else {
        Vec::new()
    };

    //let output_sources = if let Some(data) = matches.values_of("output") {
        //let output_sources: Vec<String> = data.map(|e| e.to_string()).collect();
        //info!(
            //"Selected {} data sources as input to computation.",
            //output_sources.len()
        //);
        //output_sources
    //} else {
        //Vec::new()
    //};

    //let enable_clock = matches.is_present("enable-clock");
    //let dump_stdout = matches.is_present("dump-stdout");
    //let dump_stderr = matches.is_present("dump-stderr");

    let environment_variables = match matches.get_many::<String>("env") {
        None => Vec::new(),
        Some(x) => x
            .map(|e| {
                let n = e.find('=').unwrap();
                (e[0..n].to_string(), e[n + 1..].to_string())
            })
            .collect(),
    };

    //let enable_strace = matches.is_present("strace");

    Ok(CommandLineOptions {
        input_sources,
        //output_sources,
        execution_strategy,
        //dump_stdout,
        //dump_stderr,
        //enable_clock,
        environment_variables,
        //enable_strace,
        native_modules_names,
        native_modules_entry_points,
        native_modules_special_files,
        pipeline,
    })
}

/// Entry: reads the static configuration and the command line parameters,
/// parsing both and then starts provisioning the Veracruz host state, before
/// invoking the entry point.
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let cmdline = parse_command_line()?;
    info!("Command line read successfully.");

    let permission = cmdline.input_sources.iter().map(|s| (PathBuf::from(s), FilePermissions{read: true, write: true, execute: true})).collect::<HashMap<_, _>>();

    // Construct the native module table
    info!("Serializing native modules.");

    assert_eq!(
        cmdline.native_modules_names.len(),
        cmdline.native_modules_entry_points.len()
    );
    assert_eq!(
        cmdline.native_modules_entry_points.len(),
        cmdline.native_modules_special_files.len()
    );

    let mut native_modules = Vec::new();
    for ((name, entry_point_path), special_file) in cmdline
        .native_modules_names
        .iter()
        .zip(&cmdline.native_modules_entry_points)
        .zip(&cmdline.native_modules_special_files)
    {
        // Add a backslash (VFS requirement)
        //let special_file = enforce_leading_slash(special_file.to_str()
        //.ok_or(
            //anyhow!("Fail to convert special_file to str."),
        //)?).into_owned();

        let nm_type = if entry_point_path == &PathBuf::from("") {
            NativeModuleType::Static {
                special_file: PathBuf::from(special_file),
            }
        } else {
            NativeModuleType::Dynamic {
                special_file: PathBuf::from(special_file),
                entry_point: entry_point_path.to_path_buf(),
            }
        };
        native_modules.push(NativeModule::new(name.to_string(), nm_type));
    }

    //let mut vfs = FileSystem::new(right_table, native_modules)?;
    //load_input_sources(&cmdline.input_sources, &mut vfs)?;

    info!("Data sources loaded.");

    // Execute the pipeline with the supplied environment

    let env = Environment {
        environment_variables: cmdline.environment_variables,
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
