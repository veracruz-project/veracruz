//! Proxy Attestation Server management
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use reqwest;
use std::{convert::TryInto, fs::File, io::Read};

static PROVISIONING_URL_BASE: &str = "127.0.0.1:8888";

pub struct ProxyChildren {
    vts_child: std::process::Child,
    provisioning_child: std::process::Child,
    proxy_child: std::process::Child,
}

impl Drop for ProxyChildren {
    fn drop(&mut self) {
        signal::kill(
            Pid::from_raw(self.vts_child.id().try_into().unwrap()),
            Signal::SIGTERM,
        )
        .unwrap();
        signal::kill(
            Pid::from_raw(self.provisioning_child.id().try_into().unwrap()),
            Signal::SIGTERM,
        )
        .unwrap();
        signal::kill(
            Pid::from_raw(self.proxy_child.id().try_into().unwrap()),
            Signal::SIGTERM,
        )
        .unwrap();
    }
}

#[allow(dead_code)] // FIXME
pub const CA_CERT: &'static str = "CACert.pem";

pub fn proxy_attestation_setup(
    proxy_attestation_server_url: String,
    proxy_start_dir: &String,
) -> ProxyChildren {
    let vts_log_file = File::create("/tmp/vts.log").unwrap();
    let prov_log_file = File::create("/tmp/provisioning.log").unwrap();
    let proxy_log_file = File::create("/tmp/proxy.log").unwrap();
    let vts_child = std::process::Command::new("/opt/veraison/vts/vts")
        .current_dir("/opt/veraison/vts")
        .stdout(vts_log_file)//std::process::Stdio::null())
        .spawn()
        .expect("vts died");
    let provisioning_child = std::process::Command::new("/opt/veraison/provisioning/provisioning")
        .current_dir("/opt/veraison/provisioning")
        .stdout(prov_log_file) //std::process::Stdio::null())
        .spawn()
        .expect("provision died");
    let proxy_child = std::process::Command::new("/opt/veraison/proxy_attestation_server")
        .current_dir(proxy_start_dir)
        .arg("-l")
        .arg(&proxy_attestation_server_url)
        .stdout(proxy_log_file) //std::process::Stdio::null())
        .spawn()
        .expect("Proxy Attestation Service died");

    // Poll the proxy service until it is up
    poll_until_status(&format!("http://{:}", proxy_attestation_server_url));

    // Poll the provisioning service until it is up
    poll_until_status(&format!("http://{:}", PROVISIONING_URL_BASE));

    provision_file("/opt/veraison/psa_corim.cbor", "http://arm.com/psa/iot/1");

    provision_file("/opt/veraison/nitro_corim.cbor", "http://aws.com/nitro");

    provision_file("/opt/veraison/amd_sev_snp_corim.cbor", "https://amd.com/sev-snp");
    return ProxyChildren {
        vts_child: vts_child,
        provisioning_child: provisioning_child,
        proxy_child: proxy_child,
    };
}

fn poll_until_status(root_url: &str) {
    // Poll the service until it is up
    // when the get returns a non-error Result (and thus receives a 404 status) for the non-existent path used below, the server is up
    let provision_poll_url = format!("{:}/foo", root_url);
    let mut result = reqwest::blocking::get(&provision_poll_url);
    while result.is_err() {
        println!("Looping because result is:{:?}", result);
        std::thread::sleep(std::time::Duration::from_millis(500));
        result = reqwest::blocking::get(&provision_poll_url);
    }
}

fn provision_file(corim_filename: &str, profile: &str) {
    let mut f = std::fs::File::open(&corim_filename).expect("no file found");
    let metadata = std::fs::metadata(&corim_filename).expect("unable to read metadata");
    let mut psa_corim = vec![0; metadata.len() as usize];
    f.read(&mut psa_corim).expect("buffer overflow");
    let client = reqwest::blocking::ClientBuilder::new()
        .timeout(None)
        .build()
        .map_err(|err| panic!("Unable to build clien tto post PSA CORIM:{:?}", err))
        .unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    let provision_submit_url = format!(
        "http://{:}/endorsement-provisioning/v1/submit",
        PROVISIONING_URL_BASE
    );
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_str(&format!(
            "application/corim-unsigned+cbor; profile={:}",
            profile
        ))
        .unwrap(),
    );
    let response = client
        .post(&provision_submit_url)
        .headers(headers)
        .body(psa_corim)
        .send()
        .unwrap();
    if !response.status().is_success() {
        panic!(
            "Failed to post CORIM file contents({:}) to provisioning service. Status:{:?}",
            corim_filename,
            response.status()
        );
    }
}
