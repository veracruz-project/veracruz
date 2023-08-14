//! Veracruz Server command-line interface
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::anyhow;
use clap::Parser;
use log::info;
use policy_utils::policy::Policy;
use std::{fs, path, process};
use veracruz_server;

#[derive(Parser, Debug)]
#[clap(rename_all = "kebab")]
struct Args {
    /// Path to policy file
    #[arg()]
    policy_path: path::PathBuf,
}

/// Entry point
fn main() {
    // parse args
    let opt = Args::parse();

    // setup logger
    env_logger::init();

    // load policy
    info!("Loading policy {:?}", opt.policy_path);
    let policy_result = fs::read_to_string(&opt.policy_path)
        .map_err(|err| anyhow!(err))
        .and_then(|policy_json| Ok((Policy::from_json(&policy_json)?, policy_json)));
    let (policy, policy_json) = match policy_result {
        Ok((policy, policy_json)) => (policy, policy_json),
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    };
    info!("Loaded policy {}", policy.policy_hash().unwrap_or("???"));

    // create Veracruz Server instance
    veracruz_server::server::server(&policy_json).unwrap();

    println!(
        "Veracruz Server running on {}",
        policy.veracruz_server_url()
    );

    loop {
        std::thread::sleep(std::time::Duration::MAX);
    }
}
