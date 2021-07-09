//! Veracruz Client command-line interface
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use structopt::StructOpt;
use std::path;
use std::process;
use veracruz_client::VeracruzClient;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use veracruz_utils::policy::parsers;
use veracruz_utils::policy::policy::Policy;
use veracruz_utils::policy::error::PolicyError;


#[derive(Debug, StructOpt)]
#[structopt(rename_all="kebab")]
struct Opt {
    /// Path to policy file
    #[structopt(parse(from_os_str))]
    policy_path: path::PathBuf,

    /// Request quiet operation
    ///
    /// Normally the state of the operation is printed to stderr so as not
    /// to mingle with stdout which may be piped from a result in the enclave,
    /// but this can turn that off.
    ///
    /// Note that unrecoverable errors will still be printed to stderr.
    #[structopt(short, long)]
    quiet: bool,

    /// Path to client certificate file
    #[structopt(short, long, parse(from_os_str))]
    identity: path::PathBuf,

    /// Path to client key file
    #[structopt(short, long, parse(from_os_str))]
    key: path::PathBuf,

    /// Specify optional program files to upload
    ///
    /// This can be in the form of "--program name", or in the form
    /// of "--program enclave_name=path" if you want to supply the file
    /// as a different name in the enclave. Multiple --program flags
    /// or a comma-separated list of files may be provided. Also
    /// accepts "-" to read from stdin.
    ///
    /// Note: This requires "PiProvider" permissions in the
    /// policy file.
    ///
    #[structopt(
        short, long, multiple=true, number_of_values=1,
        visible_alias="programs",
        parse(try_from_os_str=parsers::parse_renamable_paths)
    )]
    program: Vec<Vec<(String, path::PathBuf)>>,

    /// Specify optional data files to upload
    ///
    /// This can be in the form of "--data name", or in the form
    /// of "--data enclave_name=path" if you want to supply the file
    /// as a different name in the enclave. Multiple --data flags
    /// or a comma-separated list of files may be provided. Also
    /// accepts "-" to read from stdin.
    ///
    /// Note: This requires "DataProvider" permissions in the
    /// policy file.
    ///
    #[structopt(
        short, long, multiple=true, number_of_values=1,
        visible_alias="datas",
        parse(try_from_os_str=parsers::parse_renamable_paths)
    )]
    data: Vec<Vec<(String, path::PathBuf)>>,

    /// Specify optional output files to store results. If not provided
    /// the results will not be fetched.
    ///
    /// This can be in the form of "--result name", or in the form
    /// of "--result enclave_name=path" if you want to fetch with a
    /// different name in the enclave. Multiple --result flags
    /// or a comma-separated list of files may be provided. Also
    /// accepts "-" to write to stdout.
    ///
    /// If --no-shutdown is not provided, Veracruz Client will request a shutdown
    /// from the Sinaloa server after recieving the results.
    ///
    /// Note: This requires "ResultReader" permissions in the
    /// policy file.
    ///
    #[structopt(
        short, long, multiple=true, number_of_values=1,
        visible_alias="outputs",
        visible_alias="result",
        visible_alias="results",
        parse(try_from_os_str=parsers::parse_renamable_paths)
    )]
    output: Vec<Vec<(String, path::PathBuf)>>,

    /// Do not request a shutdown of the Sinaloa server after recieving the
    /// results. This can be useful if you have multiple result readers.
    #[structopt(short, long)]
    no_shutdown: bool,

    /// Request shutdown without requesting data.
    ///
    /// Note: This requires "ResultReader" permissions in the
    /// policy file.
    #[structopt(short, long)]
    shutdown: bool,
}

/// A macro to make printing a bit easier with support for --quiet
macro_rules! qprintln {
    ($opt:expr) => (if !$opt.quiet { eprintln!(); });
    ($opt:expr, $($arg:tt)*) => (if !$opt.quiet { eprintln!($($arg)*); });
}


/// Entry point
fn main() {
    // parse args
    let opt = Opt::from_args();

    // load policy
    let policy = fs::read_to_string(&opt.policy_path)
        .map_err(|err| PolicyError::from(err))
        .and_then(|policy_json| Policy::from_json(&policy_json));
    let policy = match policy {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    };
    qprintln!(opt, "Loaded policy {} {}",
        opt.policy_path.to_string_lossy(),
        policy.policy_hash().unwrap_or("???")
    );

    // create Veracruz Client instance
    qprintln!(opt, "Connecting to {}", policy.veracruz_server_url());
    let mut veracruz_client = match VeracruzClient::with_policy_and_hash(
        opt.identity,
        opt.key,
        policy.clone(),
        policy.policy_hash().unwrap().to_string(),
    ) {
        Ok(veracruz_client) => veracruz_client,
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    };

    let mut did_something = false;

    // send program(s)?
    for (program_name, program_path) in opt.program.iter().flatten() {
        qprintln!(opt, "Submitting <enclave>/{} from {}",
            program_name,
            match program_path.to_string_lossy().as_ref() {
                "-" => "<stdout>",
                path => path,
            });
        did_something = true;

        let program_data = if program_path == &path::PathBuf::from("-") {
            let mut program_data = Vec::new();
            match io::stdin().read_to_end(&mut program_data) {
                Ok(_) => program_data,
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::read(program_path) {
                Ok(program_data) => program_data,
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        };

        match veracruz_client.send_program(&program_name, &program_data) {
            Ok(()) => {}
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    // send data(s)?
    for (data_name, data_path) in opt.data.iter().flatten() {
        qprintln!(opt, "Submitting <enclave>/{} from {}",
            data_name,
            match data_path.to_string_lossy().as_ref() {
                "-" => "<stdout>",
                path => path,
            });
        did_something = true;

        let data_data = if data_path == &path::PathBuf::from("-") {
            let mut data_data = Vec::new();
            match io::stdin().read_to_end(&mut data_data) {
                Ok(_) => data_data,
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::read(data_path) {
                Ok(data_data) => data_data,
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        };

        match veracruz_client.send_data(data_name, &data_data) {
            Ok(()) => {}
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    // fetch result(s)?
    // TODO why does results take the path to the _binary_? can this
    // API be better?
    for (output_name, output_path) in opt.output.iter().flatten() {
        qprintln!(opt, "Reading <enclave>/{} into {}",
            output_name,
            match output_path.to_string_lossy().as_ref() {
                "-" => "<stdout>",
                path => path,
            });
        did_something = true;

        let results = match veracruz_client.get_results(output_name) {
            Ok(results) => results,
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        };

        if output_path == &path::PathBuf::from("-") {
            match io::stdout().write_all(&results) {
                Ok(()) => {},
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::write(output_path, results) {
                Ok(()) => {},
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        }
    }

    // shutdown?
    if (!opt.output.is_empty() && !opt.no_shutdown) || opt.shutdown {
        qprintln!(opt, "Shutting down enclave");
        did_something = true;

        match veracruz_client.request_shutdown() {
            Ok(()) => {}
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    if !did_something {
        qprintln!(opt, "Nothing to do");
        process::exit(2);
    }
}
