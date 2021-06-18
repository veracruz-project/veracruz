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
use std::process;
use actix_rt;
use veracruz_server;
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
    let veracruz_server = match veracruz_server::server::server(policy_path) {
        Ok(veracruz_server) => veracruz_server,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };

    // TODO support restarting in a loop?
    // TODO there's an unwrap panic that happens if we ctrl-C, need to fix
    info!("Sinaloa running on {}", policy.veracruz_server_url());
    match sys.block_on(veracruz_server) {
        Ok(_) => {},
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    }

    info!("done");
}
