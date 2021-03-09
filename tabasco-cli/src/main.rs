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
use std::process;
use actix_rt;
use std::env;
use proxy_attestation_server;
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

    /// Enable/disable debugging
    #[structopt(long)]
    debug: bool,
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
    let tabasco_server = match proxy_attestation_server::server::server(
        policy.proxy_attestation_server_url().clone(),
        opt.debug
    ) {
        Ok(tabasco_server) => tabasco_server,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };

    info!("Tabasco running on {}", policy.proxy_attestation_server_url());
    match sys.block_on(tabasco_server) {
        Ok(()) => {}
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    }

    info!("done");
}
