//! AMD SEV-SNP Veracruz Server
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
mod server;
use veracruz_server::VeracruzServer;

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

    // create Veracruz Server instance
    let server = Box::new(server::VeracruzServerSev::new(&policy_json).unwrap());

    veracruz_server::server::server(&policy_json, server).unwrap();
    println!(
        "Veracruz Server running on {}",
        policy.veracruz_server_url()
    );

    loop {
        std::thread::sleep(std::time::Duration::MAX);
    }
}


// fn main() {
//     let cid: u32 = 3; // TODO: Don't hard-code this
//     let port: u32 = 5005;

//     let sockaddr = SockAddr::new_vsock(cid, port);
//     let socket_fd = socket(
//         AddressFamily::Vsock,
//         SockType::Stream,
//         SockFlag::empty(),
//         None,
//     ).unwrap();
//     setsockopt(socket_fd, ReuseAddr, &true).unwrap();
//     setsockopt(socket_fd, ReusePort, &true).unwrap();
//     connect(socket_fd, &sockaddr).unwrap();
//     loop {
//         let message: String = "Hello, SEV Enclave".to_string();
//         println!("sending message:{:?}", message);
//         send_buffer(socket_fd, message.as_bytes()).unwrap();
//         let received_bytes = receive_buffer(socket_fd).unwrap();
//         let received_message = String::from_utf8(received_bytes).unwrap();
//         println!("received message:{:?}", received_message);
//     }
// }
