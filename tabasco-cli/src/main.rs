//! Tabasco command-line interface
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
use std::env;
use tabasco;
use veracruz_utils;


#[derive(Debug, StructOpt)]
#[structopt(rename_all="kebab")]
struct Opt {
    /// Path to policy file
    #[structopt(parse(from_os_str))]
    policy_path: path::PathBuf,

    /// URL or path to database, may also be provided through the
    /// DATABASE_URL environment variable
    #[structopt(long)]
    database_url: Option<String>,
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
    // TODO move this functionality into VeracruzPolicy?
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

    // needs a database URL
    if let Some(url) = opt.database_url {
        env::set_var("DATABASE_URL", url);
    }
    match env::var("DATABASE_URL") {
        Ok(url) => {
            info!("Using database {:?}", url);
        }
        Err(_) => {
            error!("No database URL provided, need --database-url");
            process::exit(1);
        }
    }

    // create Actix runtime
    let mut sys = actix_rt::System::new("Tabasco Server");

    // create Tabasco instance
    let tabasco_server = match tabasco::server::server(
        policy.tabasco_url().clone()
    ) {
        Ok(tabasco_server) => tabasco_server,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };

    info!("Tabasco running on {}", policy.tabasco_url());
    match sys.block_on(tabasco_server) {
        Ok(()) => {}
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    }

    info!("done");
}
