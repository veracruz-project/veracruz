//! Veracruz Server command-line interface
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use actix_rt;
use log::info;
use policy_utils::{error::PolicyError, policy::Policy};
use std::{fs, path, process};
use structopt::StructOpt;
use veracruz_server;

#[derive(Debug, StructOpt)]
#[structopt(rename_all = "kebab")]
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
    env_logger::init();

    // load policy
    info!("Loading policy {:?}", opt.policy_path);
    let policy_result = fs::read_to_string(&opt.policy_path)
        .map_err(|err| PolicyError::from(err))
        .and_then(|policy_json| Ok((Policy::from_json(&policy_json)?, policy_json)));
    let (policy, policy_json) = match policy_result {
        Ok((policy, policy_json)) => (policy, policy_json),
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    };
    info!("Loaded policy {}", policy.policy_hash().unwrap_or("???"));

    // create Actix runtime
    let sys = actix_rt::System::new();

    // create Veracruz Server instance
    let veracruz_server = match veracruz_server::server::server(&policy_json) {
        Ok(veracruz_server) => veracruz_server,
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    };

    println!(
        "Veracruz Server running on {}",
        policy.veracruz_server_url()
    );
    match sys.block_on(veracruz_server) {
        Ok(_) => {}
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    }
}
