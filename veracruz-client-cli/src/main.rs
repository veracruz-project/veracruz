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
use veracruz_client::VeracruzClient;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::ffi;
use veracruz_utils::platform::Platform;


/// parser for file paths either in the form of
/// --program=a.wasm or --program=b:a.wasm if a file should
/// be provided as a different name.
///
/// Also accepts comma-separated lists of files.
///
/// Note we can't fail, because a malformed string may be
/// interpreted as a really ugly filename. Fortunately these
/// sort of mistakes should still be caught by a later
/// "file-not-found" error.
fn parse_file_paths(
    s: &ffi::OsStr
) -> Result<Vec<(String, path::PathBuf)>, ffi::OsString> {
    match s.to_str() {
        Some(s) => {
            Ok(
                s.split(",")
                    .map(|s| {
                        // TODO should we actually use = as a separator? more
                        // common in CLIs
                        match s.splitn(2, ":").collect::<Vec<_>>().as_slice() {
                            [name, path] => (
                                String::from(*name),
                                path::PathBuf::from(*path)
                            ),
                            [path] => (
                                String::from(*path),
                                path::PathBuf::from(*path)
                            ),
                            _ => unreachable!(),
                        }
                    })
                    .collect::<Vec<_>>()
            )
        },
        None => {
            Err(ffi::OsString::from(
                format!("invalid path: {:?}", s)
            ))
        }
    }
}


#[derive(Debug, StructOpt)]
#[structopt(rename_all="kebab")]
struct Opt {
    /// Path to policy file
    #[structopt(parse(from_os_str))]
    policy_path: path::PathBuf,

    /// Target enclave platform
    #[structopt(short, long)]
    target: Platform,

    /// Path to client certificate file
    #[structopt(short, long, parse(from_os_str))]
    identity: path::PathBuf,

    /// Path to client key file
    #[structopt(short, long, parse(from_os_str))]
    key: path::PathBuf,

    /// Specify optional program files to upload
    ///
    /// This can be in the form of "--program=name", or in the form
    /// of "--program=enclave_name:name" if you want to supply the file
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
        parse(try_from_os_str=parse_file_paths)
    )]
    program: Vec<Vec<(String, path::PathBuf)>>,

    /// Specify optional data files to upload
    ///
    /// This can be in the form of "--data=name", or in the form
    /// of "--data=enclave_name:name" if you want to supply the file
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
        parse(try_from_os_str=parse_file_paths)
    )]
    data: Vec<Vec<(String, path::PathBuf)>>,

    // TODO does this need to be vec?
    /// Specify optional output files to store results. If not provided
    /// the results will not be fetched.
    ///
    /// This can be in the form of "--result=name", or in the form
    /// of "--result=enclave_name:name" if you want to fetch with a
    /// different name in the enclave. Multiple --result flags
    /// or a comma-separated list of files may be provided. Also
    /// accepts "-" to write to stdout.
    ///
    /// If --no-shutdown is not provided, Durango will request a shutdown
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
        parse(try_from_os_str=parse_file_paths)
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
    let (policy, policy_hash) = match veracruz_utils::policy::policy::policy_and_hash_from_file(
        &opt.policy_path
    ) {
        Ok((policy, policy_hash)) => (policy, policy_hash),
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Loaded policy {}", policy_hash);

    // create Durango instance
    // TODO allow AsRef<VeracruzPolicy>?
    let mut durango = match VeracruzClient::with_policy_and_hash(
        opt.identity,
        opt.key,
        policy.clone(),
        policy_hash,
        &opt.target,
    ) {
        Ok(durango) => durango,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Connected to {}", policy.veracruz_server_url());

    let mut did_something = false;

    // send program(s)?
    for (program_name, program_path) in opt.program.iter().flatten() {
        did_something = true;

        let program_data = if program_path == &path::PathBuf::from("-") {
            let mut program_data = Vec::new();
            match io::stdin().read_to_end(&mut program_data) {
                Ok(_) => program_data,
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::read(program_path) {
                Ok(program_data) => program_data,
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        };

        match durango.send_program(&program_name, &program_data) {
            Ok(()) => {}
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }

        info!("Submitted program {:?}", program_path);
    }

    // send data(s)?
    for (data_name, data_path) in opt.data.iter().flatten() {
        did_something = true;

        let data_data = if data_path == &path::PathBuf::from("-") {
            let mut data_data = Vec::new();
            match io::stdin().read_to_end(&mut data_data) {
                Ok(_) => data_data,
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::read(data_path) {
                Ok(data_data) => data_data,
                Err(err) => {
                    error!("{}", err);
                    process::exit(1);
                }
            }
        };

        match durango.send_data(data_name, &data_data) {
            Ok(()) => {}
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }

        info!("Submitted data {:?}", data_path);
    }

    // fetch result(s)?
    for (output_name, output_path) in opt.output.iter().flatten() {
        did_something = true;

        let results = match durango.get_results(output_name) {
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
    if (!opt.output.is_empty() && !opt.no_shutdown) || opt.shutdown {
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
