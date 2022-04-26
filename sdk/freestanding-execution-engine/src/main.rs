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
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use clap::{App, Arg};
use execution_engine::{execute, fs::FileSystem, Options};
use log::*;
use policy_utils::{
    principal::{ExecutionStrategy, Principal},
    CANONICAL_STDERR_FILE_PATH, CANONICAL_STDIN_FILE_PATH, CANONICAL_STDOUT_FILE_PATH,
};
use std::{
    collections::HashMap,
    error::Error,
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
    vec::Vec,
};
use wasi_types::Rights;

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
const AUTHORS: &str = "The Veracruz Development Team.  See the file `AUTHORS.markdown` in the \
                       Veracruz root directory for detailed authorship information.";
/// Application version number.
const VERSION: &str = "pre-alpha";

////////////////////////////////////////////////////////////////////////////////
// Command line options and parsing.
////////////////////////////////////////////////////////////////////////////////

/// A struct capturing all of the command line options passed to the program.
struct CommandLineOptions {
    /// The list of file names passed as input data-sources.
    input_sources: Vec<String>,
    /// The list of file names passed as ouput.
    output_sources: Vec<String>,
    /// The paths passed as the WASM programs to be executed (in order).
    program_sources: Vec<String>,
    /// The execution strategy to use when performing the computation.
    execution_strategy: ExecutionStrategy,
    /// Whether the contents of `stdout` should be dumped before exiting.
    dump_stdout: bool,
    /// Whether the contents of `stderr` should be dumped before exiting.
    dump_stderr: bool,
    /// Whether clock functions (`clock_getres()`, `clock_gettime()`) should be
    /// enabled.
    enable_clock: bool,
    /// Environment variables for the program.
    environment_variables: Vec<(String, String)>,
    /// Command-line arguments for the program, including argv[0].
    program_arguments: Vec<String>,
    /// Whether strace is enabled.
    enable_strace: bool,
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
            Arg::with_name("input")
                .short("i")
                .long("input-source")
                .value_name("DIRECTORIES")
                .help(
                    "Space-separated paths to the input directories on disk. The directories are \
                     copied into the root directory in Veracruz space. All programs are granted \
                     with read capabilities.",
                )
                .multiple(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output-source")
                .value_name("DIRECTORIES")
                .help(
                    "Space-separated paths to the output directories. The directories are copied \
                     into disk on the host. All program are granted with write capabilities.",
                )
                .multiple(true),
        )
        .arg(
            Arg::with_name("program")
                .short("p")
                .long("program")
                .value_name("FILE")
                .help("Paths to the WASM binary to be executed. It executes in order.")
                .multiple(true)
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
                ),
        )
        .arg(
            Arg::with_name("dump-stdout")
                .short("d")
                .long("dump-stdout")
                .help("Whether the contents of stdout should be dumped before exiting"),
        )
        .arg(
            Arg::with_name("dump-stderr")
                .short("e")
                .long("dump-stderr")
                .help("Whether the contents of stderr should be dumped before exiting"),
        )
        .arg(
            Arg::with_name("enable-clock")
                .short("c")
                .long("enable-clock")
                .help(
                    "Whether clock functions (`clock_getres()`, `clock_gettime()`) should be \
                     enabled.",
                ),
        )
        .arg(
            Arg::with_name("arg")
                .long("arg")
                .help("Specify a command-line argument.")
                .value_name("ARG")
                .multiple(true),
        )
        .arg(
            Arg::with_name("env")
                .long("env")
                .help("Specify an environment variable and value (VAR=VAL).")
                .value_name("VAR=VAL")
                .multiple(true),
        )
        .arg(
            Arg::with_name("strace")
                .long("strace")
                .help("Enable strace-like output for WASI calls."),
        )
        .get_matches();

    info!("Parsed command line.");

    let execution_strategy = {
        let strategy = matches.value_of("execution-strategy").unwrap_or("jit");
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

    let program_sources = if let Some(data) = matches.values_of("program") {
        let program_sources: Vec<String> = data.map(|e| e.to_string()).collect();
        info!("Using '{:?}' as our WASM executable.", program_sources);
        program_sources
    } else {
        return Err("No binary file provided.".into());
    };
    let input_sources = if let Some(data) = matches.values_of("input") {
        let input_sources: Vec<String> = data.map(|e| e.to_string()).collect();
        info!(
            "Selected {} data sources as input to computation.",
            input_sources.len()
        );
        input_sources
    } else {
        Vec::new()
    };

    let output_sources = if let Some(data) = matches.values_of("output") {
        let output_sources: Vec<String> = data.map(|e| e.to_string()).collect();
        info!(
            "Selected {} data sources as input to computation.",
            output_sources.len()
        );
        output_sources
    } else {
        Vec::new()
    };

    let enable_clock = matches.is_present("enable-clock");
    let dump_stdout = matches.is_present("dump-stdout");
    let dump_stderr = matches.is_present("dump-stderr");

    let environment_variables = match matches.values_of("env") {
        None => Vec::new(),
        Some(x) => x
            .map(|e| {
                let n = e.find('=').unwrap();
                (e[0..n].to_string(), e[n + 1..].to_string())
            })
            .collect(),
    };
    let program_arguments = match matches.values_of("arg") {
        None => Vec::new(),
        Some(x) => x.map(|e| e.to_string()).collect(),
    };
    let enable_strace = matches.is_present("strace");

    Ok(CommandLineOptions {
        input_sources,
        output_sources,
        program_sources,
        execution_strategy,
        dump_stdout,
        dump_stderr,
        enable_clock,
        environment_variables,
        program_arguments,
        enable_strace,
    })
}

/// Loads the specified data sources, as provided on the command line, for
/// reading and massages them into metadata frames, ready for
/// the computation.  May abort the program if something goes wrong when reading
/// any data source.
fn load_input_sources(
    input_sources: &[String],
    vfs: &mut FileSystem,
) -> Result<(), Box<dyn Error>> {
    for file_path in input_sources.iter() {
        let file_path = Path::new(file_path);
        load_input_source(&file_path, vfs)?;
    }
    Ok(())
}

fn load_input_source<T: AsRef<Path>>(
    file_path: T,
    vfs: &mut FileSystem,
) -> Result<(), Box<dyn Error>> {
    let file_path = file_path.as_ref();
    info!("Loading data source '{:?}'.", file_path);
    if file_path.is_file() {
        let mut file = File::open(file_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        vfs.write_file_by_absolute_path(&Path::new("/").join(file_path), buffer, false)?;
    } else if file_path.is_dir() {
        for dir in file_path.read_dir()? {
            load_input_source(&dir?.path(), vfs)?;
        }
    } else {
        return Err(format!("Error on load {:?}", file_path).into());
    }
    Ok(())
}

/// Entry: reads the static configuration and the command line parameters,
/// parsing both and then starts provisioning the Veracruz host state, before
/// invoking the entry point.
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut cmdline = parse_command_line()?;
    info!("Command line read successfully.");

    // Convert the program paths to absolute if needed.
    cmdline.program_sources.iter_mut().for_each(|e| {
        if !e.starts_with("/") {
            e.insert(0, '/');
        }
    });

    // Contruct the right table
    let mut right_table = HashMap::new();
    // Contruct file table for all programs
    let mut file_table = HashMap::new();
    let read_right = Rights::PATH_OPEN | Rights::FD_READ | Rights::FD_SEEK | Rights::FD_READDIR;
    let write_right = read_right
        | Rights::FD_WRITE
        | Rights::PATH_CREATE_FILE
        | Rights::PATH_FILESTAT_SET_SIZE
        | Rights::PATH_CREATE_DIRECTORY;

    // Set up standard streams table
    file_table.insert(PathBuf::from(CANONICAL_STDIN_FILE_PATH), read_right);
    file_table.insert(PathBuf::from(CANONICAL_STDOUT_FILE_PATH), write_right);
    file_table.insert(PathBuf::from(CANONICAL_STDERR_FILE_PATH), write_right);
    // Add read permission to input path
    for file_path in cmdline.input_sources.iter() {
        // NOTE: inject the root path.
        file_table.insert(Path::new("/").join(file_path), read_right);
    }
    // Add write permission to output path
    for file_path in cmdline.output_sources.iter() {
        // NOTE: inject the root path.
        file_table.insert(Path::new("/").join(file_path), write_right);
    }

    // Insert the file right for all programs
    for prog_path in &cmdline.program_sources {
        let program_id = Principal::Program(prog_path.to_string());
        right_table.insert(program_id.clone(), file_table.clone());
    }

    // Grant the super user read access to any file under the root. This is
    // used internally to read the program on behalf of the executing party
    let mut su_read_rights = HashMap::new();
    su_read_rights.insert(
        PathBuf::from("/"),
        Rights::PATH_OPEN | Rights::FD_READ | Rights::FD_SEEK | Rights::FD_READDIR,
    );

    info!("The final right tables: {:?}", right_table);

    let mut vfs = FileSystem::new(right_table)?;

    load_input_sources(&cmdline.input_sources, &mut vfs)?;
    info!("Data sources loaded.");

    info!("Invoking programs in order {:?}.", cmdline.program_sources);

    for prog_path in &cmdline.program_sources {
        let main_time = Instant::now();
        let options = Options {
            environment_variables: cmdline.environment_variables.clone(),
            program_arguments: cmdline.program_arguments.clone(),
            enable_clock: cmdline.enable_clock,
            enable_strace: cmdline.enable_strace,
            ..Default::default()
        };
        let program = vfs.read_file_by_absolute_path(prog_path)?;
        let return_code = execute(
            &cmdline.execution_strategy,
            vfs.spawn(&Principal::Program(prog_path.to_string()))?,
            program,
            options,
        )?;
        info!("return code of {}: {:?}", prog_path, return_code);
        info!(
            "time on {}: {} micro seconds",
            prog_path,
            main_time.elapsed().as_micros()
        );

        // Dump contents of stdout
        if cmdline.dump_stdout {
            let buf = vfs.read_stdout()?;
            let stdout_dump = std::str::from_utf8(&buf)?;
            print!(
                "---- stdout dump ----\n{}---- stdout dump end ----\n",
                stdout_dump
            );
            std::io::stdout().flush()?;
        }

        // Dump contents of stderr
        if cmdline.dump_stderr {
            let buf = vfs.read_stderr()?;
            let stderr_dump = std::str::from_utf8(&buf)?;
            eprint!(
                "---- stderr dump ----\n{}---- stderr dump end ----\n",
                stderr_dump
            );
            std::io::stderr().flush()?;
        }
    }

    // Map all output directories
    for file_path in cmdline.output_sources.iter() {
        for (output_path, buf) in vfs
            .read_all_files_by_absolute_path(Path::new("/").join(file_path))?
            .iter()
        {
            let output_path = output_path.strip_prefix("/").unwrap_or(output_path);
            if let Some(parent_path) = output_path.parent() {
                if parent_path != Path::new("") {
                    create_dir_all(parent_path)?;
                }
            }
            let mut to_write = File::create(output_path)?;
            to_write.write_all(&buf)?;

            // Try to decode
            let decode: String = match postcard::from_bytes(buf) {
                Ok(o) => o,
                Err(_) => match std::str::from_utf8(buf) {
                    Ok(oo) => oo.to_string(),
                    Err(_) => "(Cannot Parse as a utf8 string)".to_string(),
                },
            };
            info!("{:?}: {:?}", output_path, decode);
        }
    }
    Ok(())
}
