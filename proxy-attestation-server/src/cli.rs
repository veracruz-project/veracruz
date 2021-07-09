//! Proxy Attestation Server command-line interface
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
use std::fs;
use proxy_attestation_server;
use veracruz_utils::policy::policy::Policy;
use veracruz_utils::policy::error::PolicyError;


#[derive(Debug, StructOpt)]
#[structopt(rename_all="kebab")]
struct Opt {
    /// Path to policy file
    #[structopt(parse(from_os_str))]
    policy_path: path::PathBuf,

    /// Path to CA certificate
    #[structopt(long, parse(from_os_str))]
    ca_cert: path::PathBuf,

    /// Path to CA private key
    #[structopt(long, parse(from_os_str))]
    ca_key: path::PathBuf,

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
    let policy = fs::read_to_string(&opt.policy_path)
        .map_err(|err| PolicyError::from(err))
        .and_then(|policy_json| Policy::from_json(&policy_json));
    let policy = match policy {
        Ok(policy) => policy,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Loaded policy {}", policy.policy_hash().unwrap_or("???"));

    // log the CA cert
    info!("Using CA certificate {:?}", opt.ca_cert);

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
    let mut sys = actix_rt::System::new("Proxy Attestation Server");

    // create Proxy Attestation Server instance
    let proxy_attestation_server = match proxy_attestation_server::server::server(
        policy.proxy_attestation_server_url().clone(),
        &opt.ca_cert,
        &opt.ca_key,
        opt.debug
    ) {
        Ok(proxy_attestation_server) => proxy_attestation_server,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };

    info!("Proxy Attestation Server running on {}", policy.proxy_attestation_server_url());
    match sys.block_on(proxy_attestation_server) {
        Ok(()) => {}
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    }

    info!("done");
}
