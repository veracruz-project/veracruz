use crate::common::util::*;
use actix_rt::System;
use log::info;
use proxy_attestation_server;
use std::sync::Once;

pub static PROXY_ATTESTATION_SETUP: Once = Once::new();

pub const CA_CERT: &'static str = "CACert.pem";
pub const CA_KEY: &'static str = "CAKey.pem";

pub fn proxy_attestation_setup(proxy_attestation_server_url: String) {
    PROXY_ATTESTATION_SETUP.call_once(|| {
        info!("Proxy attestation server: initialize.");

        let _main_loop_handle = std::thread::spawn(|| {
            let sys = System::new();
            info!(
                "spawned thread calling server with url:{:?}",
                proxy_attestation_server_url
            );
            let debug_flag = if cfg!(feature = "debug") { true } else { false };
            let server = proxy_attestation_server::server::server(
                proxy_attestation_server_url,
                cert_key_dir(CA_CERT).as_path(),
                cert_key_dir(CA_KEY).as_path(),
                debug_flag,
            )
            .unwrap();
            sys.block_on(server).unwrap();
        });
    });
    // Sleep to wait for the proxy attestation server to start
    std::thread::sleep(std::time::Duration::from_millis(100));
}
