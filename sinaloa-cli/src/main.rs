//! Sinaloa command-line interface
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
use log::{info, error};
use ring;
use hex;
use std::process;
use actix_rt;
use sinaloa;
use veracruz_utils;


#[derive(Debug, StructOpt)]
#[structopt(rename_all="kebab")]
struct Opt {
    /// Path to policy file
    #[structopt(parse(from_os_str))]
    policy_path: path::PathBuf,
}


/// Entry point
fn main() {
    // parse args
    let opt = Opt::from_args();

    // setup logger
    env_logger::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

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
            policy_json.as_str()
    ) {
        Ok(policy) => policy,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Loaded policy {}", policy_hash);

    // need to convert to str for Sinaloa
    // TODO allow Sinaloa to accept Paths?
    let policy_path = match opt.policy_path.to_str() {
        Some(policy_path) => policy_path,
        None => {
            error!("Invalid policy_path (not utf8?)");
            process::exit(1);
        }
    };

    // create Actix runtime
    let mut sys = actix_rt::System::new("Sinaloa Server");

    // create Sinaloa server instance
    let sinaloa_server = match sinaloa::server::server(policy_path) {
        Ok(sinaloa_server) => sinaloa_server,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };

    // TODO support restarting in a loop?
    // TODO there's an unwrap panic that happens if we ctrl-C, need to fix
    info!("Sinaloa running on {}", policy.sinaloa_url());
    match sys.block_on(sinaloa_server) {
        Ok(_) => {},
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    }

    info!("done");
}
