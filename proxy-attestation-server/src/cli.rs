//! Proxy Attestation Server command-line interface
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
use env_logger;
use log::info;
use proxy_attestation_server;
use std::{path, process};
use structopt::StructOpt;

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
#[structopt(rename_all = "kebab")]
struct Opt {
    /// URL to serve on
    #[structopt(parse(from_str=parse_bind_addr))]
    url: String,

    /// Path to CA certificate
    #[structopt(long, parse(from_os_str))]
    ca_cert: path::PathBuf,

    /// Path to CA private key
    #[structopt(long, parse(from_os_str))]
    ca_key: path::PathBuf,

    /// Enable/disable debugging
    #[structopt(long)]
    debug: bool,
}

/// Entry point
fn main() {
    // parse args
    let opt = Opt::from_args();

    // setup logger
    env_logger::init();

    // log the CA cert
    info!("Using CA certificate {:?}", opt.ca_cert);

    // create Actix runtime
    let sys = actix_rt::System::new();

    // create Proxy Attestation Server instance
    let proxy_attestation_server = match proxy_attestation_server::server::server(
        &opt.url,
        &opt.ca_cert,
        &opt.ca_key,
        opt.debug,
    ) {
        Ok(proxy_attestation_server) => proxy_attestation_server,
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    };

    println!("Proxy Attestation Server running on {}", opt.url);
    match sys.block_on(proxy_attestation_server) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    }
}
