//! Durango command-line interface
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
use env_logger;
use log::{info, warn, error};
use std::process;
use durango::Durango;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;


#[derive(Debug, StructOpt)]
#[structopt(rename_all="kebab")]
struct Opt {
    /// Path to policy file
    #[structopt(parse(from_os_str))]
    policy_path: path::PathBuf,

    /// Path to client certificate file
    #[structopt(short, long, parse(from_os_str))]
    identity: path::PathBuf,

    /// Path to client key file
    #[structopt(short, long, parse(from_os_str))]
    key: path::PathBuf,

    /// Specify optional program file to upload
    ///
    /// Accepts "-" to read from stdin
    ///
    /// Note: This requires "PiProvider" permissions in the
    /// policy file.
    #[structopt(short, long, parse(from_os_str))]
    program: Option<path::PathBuf>,

    /// Specify optional data file to upload
    ///
    /// Accepts "-" to read from stdin
    ///
    /// Note: This requires "DataProvider" permissions in the
    /// policy file.
    #[structopt(short, long, multiple=true, number_of_values=1, parse(from_os_str))]
    data: Vec<path::PathBuf>,

    /// Specify optional output file to store results. If not provided
    /// the results will not be fetched.
    ///
    /// If --no-shutdown is not provided, Durango will request a shutdown
    /// from the Sinaloa server after recieving the results.
    ///
    /// Accepts "-" to write to stdout
    ///
    /// Note: This requires "ResultReader" permissions in the
    /// policy file.
    #[structopt(short, long, visible_alias="result", parse(from_os_str))]
    output: Option<path::PathBuf>,

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


/// Entry point
fn main() {
    // parse args
    let opt = Opt::from_args();

    // setup logger
    // TODO, unlike sinaloa/tabasco, this is a client, do we really
    // need timestamps/context?
    env_logger::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    // load policy
    info!("Loading policy {:?}", opt.policy_path);
    let (policy, policy_hash) = match veracruz_utils::policy_and_hash_from_file(
        &opt.policy_path
    ) {
        Ok((policy, policy_hash)) => (policy, policy_hash),
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Loaded policy {}", policy_hash);

    // need to convert to str for Durango
    // TODO allow Durango to accept Paths?
    let client_cert_path = match opt.identity.to_str() {
        Some(client_cert_path) => client_cert_path,
        None => {
            error!("Invalid client_cert_path (not utf8?)");
            process::exit(1);
        }
    };
    let client_key_path = match opt.key.to_str() {
        Some(client_key_path) => client_key_path,
        None => {
            error!("Invalid client_key_path (not utf8?)");
            process::exit(1);
        }
    };

    // create Durango instance
    // TODO allow AsRef<VeracruzPolicy>?
    let mut durango = match Durango::with_policy_and_hash(
        opt.identity,
        opt.key,
        policy.clone(),
        policy_hash,
    ) {
        Ok(durango) => durango,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Connected to {}", policy.sinaloa_url());

    let mut did_something = false;

    // send program?
    if let Some(ref program_path) = opt.program {
        did_something = true;

        let program = if program_path == &path::PathBuf::from("-") {
            let mut program = Vec::new();
            match io::stdin().read_to_end(&mut program) {
                Ok(_) => program,
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::read(program_path) {
                Ok(program) => program,
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        };

        match durango.send_program(&program) {
            Ok(()) => {}
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }

        info!("Submitted program {:?}", program_path);
    }

    // send data(s)?
    // TODO can we specify these in any order?
    for data_path in opt.data.iter() {
        did_something = true;

        let data = if data_path == &path::PathBuf::from("-") {
            let mut data = Vec::new();
            match io::stdin().read_to_end(&mut data) {
                Ok(_) => data,
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::read(data_path) {
                Ok(data) => data,
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        };

        match durango.send_data(&data) {
            Ok(()) => {}
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }

        info!("Submitted data {:?}", data_path);
    }

    if let Some(ref output_path) = opt.output {
        did_something = true;

        let results = match durango.get_results() {
            Ok(results) => results,
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        };

        // TODO "post_mexico_city started prints" causes problems with stdout
        if output_path == &path::PathBuf::from("-") {
            match io::stdout().write_all(&results) {
                Ok(()) => {},
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::write(output_path, results) {
                Ok(()) => {},
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        }

        info!("Read results into {:?}", output_path);
    }

    // shutdown?
    if (opt.output.is_some() && !opt.no_shutdown) || opt.shutdown {
        did_something = true;

        match durango.request_shutdown() {
            Ok(()) => {}
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }

        info!("Shutdown server");
    }

    if !did_something {
        warn!("Nothing to do");
        process::exit(2);
    }
}
