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

use anyhow::anyhow;
use log::info;
use policy_utils::policy::Policy;
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

    // create runtime
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|err| {
        eprintln!("{}", err);
        process::exit(1);
    });

    // create Veracruz Server instance
    let veracruz_server = veracruz_server::server::server(&policy_json);

    println!(
        "Veracruz Server running on {}",
        policy.veracruz_server_url()
    );
    rt.block_on(async { veracruz_server.await })
        .unwrap_or_else(|err| {
            eprintln!("{}", err);
            process::exit(1);
        });
}
