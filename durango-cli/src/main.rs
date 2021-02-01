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
use ring;
use hex;
use std::process;
use rand;
use rand::Rng;
use base64;
use curl::easy::{Easy, List};
use stringreader;
use std::io::Read;
use tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync;
use durango::Durango;
use std::fs;

use sinaloa::sinaloa::*;
#[cfg(feature = "sgx")]
use sinaloa::SinaloaSGX as SinaloaEnclave;
#[cfg(feature = "tz")]
use sinaloa::SinaloaTZ as SinaloaEnclave;


// TODO version info?
// TODO what is name used for here?
// TODO do we need to understand identity?

#[derive(Debug, StructOpt)]
#[structopt(
    name="durango",
    about="Command-line interface for Durango, \
        the Rust client for Veracruz.",
    rename_all="kebab"
)]
struct Opt {
    /// Path to client certificate file
    #[structopt(parse(from_os_str))]
    client_cert_path: path::PathBuf,

    /// Path to client key file
    #[structopt(parse(from_os_str))]
    client_key_path: path::PathBuf,

    /// Path to policy file
    #[structopt(parse(from_os_str))]
    policy_path: path::PathBuf,

    /// Specify optional program file to upload
    ///
    /// Note: This requires "PiProvider" permissions in the
    /// policy file.
    #[structopt(short, long, parse(from_os_str))]
    program: Option<path::PathBuf>,

    /// Specify optional data file to upload
    ///
    /// Note: This requires "DataProvider" permissions in the
    /// policy file.
    #[structopt(short, long, parse(from_os_str))]
    data: Option<path::PathBuf>,

    /// Specify optional output file to store results. If not provided
    /// the results will not be fetched.
    ///
    /// Note: This requires "ResultReader" permissions in the
    /// policy file.
    #[structopt(short, long, parse(from_os_str))]
    output: Option<path::PathBuf>,

    /// Request a shutdown of the enclave
    ///
    /// Note: This requires "ResultReader" permissions in the
    /// policy file.
    #[structopt(short, long)]
    shutdown: bool,

    // TODO remove this from here and Sinaloa
    /// Skip attestation flow, use at your own risk
    #[structopt(long)]
    no_attestation: bool,
}


/// Entry point
fn main() {
    // parse args
    let opt = Opt::from_args();

    // setup logger
    env_logger::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    // load policy
    info!("Loading policy {:?}", opt.policy_path);
    let policy_json = match std::fs::read_to_string(&opt.policy_path) {
        Ok(policy_json) => policy_json,
        Err(_) => {
            error!("Cannot open file {:?}", opt.policy_path);
            process::exit(1);
        }
    };
    let policy_hash_bytes = ring::digest::digest(
        &ring::digest::SHA256, policy_json.as_bytes());
    let policy_hash = hex::encode(&policy_hash_bytes.as_ref().to_vec());
    let policy = match veracruz_utils::VeracruzPolicy::from_json(
            policy_json.as_str()) {
        Ok(policy) => policy,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Loaded policy {}", policy_hash);

    // need to convert to str for Durango
    // TODO allow Durango to accept Paths?
    let client_cert_path = match opt.client_cert_path.to_str() {
        Some(client_cert_path) => client_cert_path,
        _ => {
            error!("Invalid client_cert_path (not utf8?)");
            process::exit(1);
        }
    };
    let client_key_path = match opt.client_key_path.to_str() {
        Some(client_key_path) => client_key_path,
        _ => {
            error!("Invalid client_key_path (not utf8?)");
            process::exit(1);
        }
    };

    // create Durango instance
    let mut durango = match Durango::new(
        client_cert_path,
        client_key_path,
        &policy_json,
    ) {
        Ok(durango) => durango,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Connected and attested {}", policy.sinaloa_url());

    let mut did_something = false;

    // send program?
    if let Some(ref program_path) = opt.program {
        did_something = true;

        let program = match fs::read(program_path) {
            Ok(program) => program,
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        };

        match durango.send_program(&program) {
            Ok(()) => {}
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }

        info!("Submitted program \"{:?}\"", program_path);
    }

    // send data?
    if let Some(ref data_path) = opt.data {
        did_something = true;

        let data = match fs::read(data_path) {
            Ok(data) => data,
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        };

        match durango.send_data(&data) {
            Ok(()) => {}
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }

        info!("Submitted data \"{:?}\"", data_path);
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

        // TODO support "-"?
        match fs::write(output_path, results) {
            Ok(()) => {},
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }

        info!("Read results into \"{:?}\"", output_path);
    }

    // shutdown?
    if opt.shutdown {
        did_something = true;

        match durango.request_shutdown() {
            Ok(()) => {}
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }

        // TODO do we get ack?
        //info!("Shutdown successfully");
        info!("Shutdown");
    }

    if !did_something {
        warn!("Nothing to do");
    }
}