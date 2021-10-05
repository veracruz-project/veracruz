//! Veracruz Server command-line interface
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use actix_rt;
use log::info;
use std::{fs, path, process};
use structopt::StructOpt;
use veracruz_server;
use veracruz_utils::policy::{
    error::PolicyError,
    policy::Policy,
};


/// A bit of extra parsing to allow omitting addr/port
fn parse_bind_addr(s: &str) -> String {
    // Rust's SocketAddr parser requires an explicit address/port, add 0.0.0.0
    // if omitted, this lets ':3010' be used to specify only the port
    if s.starts_with(':') {
        format!("0.0.0.0{}", s)
    } else if s.ends_with(':') {
        format!("{}0", s)
    } else {
        s.to_string()
    }
}

#[derive(Debug, StructOpt)]
#[structopt(rename_all="kebab")]
struct Opt {
    /// URL to serve on
    #[structopt(parse(from_str=parse_bind_addr))]
    url: String,

    /// Optional path to policy file
    ///
    /// If a policy file is provide, the server will be started with a single
    /// enclave instance ready to compute
    ///
    #[structopt(parse(from_os_str))]
    policy_path: Option<path::PathBuf>,
}


/// Entry point
fn main() {
    // parse args
    let opt = Opt::from_args();

    // setup logger
    env_logger::init();

    // load policy
    let opt_policy_json = match opt.policy_path {
        Some(policy_path) => {
            info!("Loading policy {:?}", policy_path);
            let policy_result = fs::read_to_string(&policy_path)
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
            Some(policy_json)
        }
        None => None
    };

    // create Actix runtime
    let mut sys = actix_rt::System::new("Veracruz Server");

    // create Veracruz Server instance
    let veracruz_server = match veracruz_server::server::server(
        &opt.url,
        opt_policy_json.as_deref(),
    ) {
        Ok(veracruz_server) => veracruz_server,
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    };

    println!("Veracruz Server running on {}", opt.url);
    match sys.block_on(veracruz_server) {
        Ok(_) => {},
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    }
}
