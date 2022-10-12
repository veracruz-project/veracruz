//! Proxy Attestation Server management
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use lazy_static::lazy_static;
use log::info;
use reqwest;
use std::{
    io::Read,
    sync::{Mutex,
           Once,
    }
};

pub static PROXY_ATTESTATION_SETUP: Once = Once::new();
pub static PROVISION_SETUP: Once = Once::new();


struct ProxyChildren {
    vts_child: std::process::Child,
    provisioning_child: std::process::Child,
    proxy_child: std::process::Child,
}

impl Drop for ProxyChildren {
    fn drop(&mut self) {
        println!("Dropping ProxyChildren");
        let _kill_ignore = self.vts_child.kill();
        let _kill_ignore = self.provisioning_child.kill();
        let _kill_ignore = self.proxy_child.kill();
    }
}

lazy_static! {
    static ref proxy_children: Mutex<Option<ProxyChildren>> = Mutex::new(None);
}

pub const CA_CERT: &'static str = "CACert.pem";

pub fn proxy_attestation_setup(proxy_attestation_server_url: String) {
    PROXY_ATTESTATION_SETUP.call_once(|| {
        info!("Proxy attestation server: initialize.");
        println!("starting vts");
        let vts_child = std::process::Command::new("/opt/veraison/vts/vts").current_dir("/opt/veraison/vts").spawn().expect("vts died");
        println!("starting provisioning service");
        let provisioning_child = std::process::Command::new("/opt/veraison/provisioning/provisioning").current_dir("/opt/veraison/provisioning").spawn().expect("provision died");
        println!("starting proxy service on url:{:?}", proxy_attestation_server_url);
        let proxy_child = std::process::Command::new("/opt/veraison/VeracruzVerifier").current_dir("/work/veracruz/workspaces/linux-host/test-collateral").arg("-l").arg(proxy_attestation_server_url).spawn().expect("Proxy Attestation Service died");            

        let mut pc_guard = proxy_children.lock().unwrap();
        *pc_guard = Some(ProxyChildren {
            vts_child: vts_child,
            provisioning_child: provisioning_child,
            proxy_child: proxy_child,
        });
    });
    // Sleep to wait for the proxy attestation server to start
    println!("sleeping while proxy service sets ups");
    std::thread::sleep(std::time::Duration::from_millis(100));
    println!("done sleeping");
    
    PROVISION_SETUP.call_once(|| {
        println!("post PSA CORIM to provisioning server");
        let corim_filename = "/opt/veraison/psa_corim.cbor";
        let mut f = std::fs::File::open(&corim_filename).expect("no file found");
        let metadata = std::fs::metadata(&corim_filename).expect("unable to read metadata");
        let mut psa_corim = vec![0; metadata.len() as usize];
        f.read(&mut psa_corim).expect("buffer overflow");
        let client = reqwest::blocking::ClientBuilder::new()
            .timeout(None)
            .build()
            .map_err(|err| panic!("Unable to build clien tto post PSA CORIM:{:?}", err)).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/corim-unsigned+cbor; profile=http://arm.com/psa/iot/1"));
        let response = client.post("http://127.0.0.1:8888/endorsement-provisioning/v1/submit")
            .headers(headers)
            .body(psa_corim)
            .send()
            .unwrap();
        if !response.status().is_success() {
            panic!("Failed to post PSA CORIM to provisioning service. Status:{:?}", response.status());
        }

        println!("post Nitro CORIM to provisioning server");
        let corim_filename = "/opt/veraison/nitro_corim.cbor";
        let mut f = std::fs::File::open(&corim_filename).expect("no file found");
        let metadata = std::fs::metadata(&corim_filename).expect("unable to read metadata");
        let mut psa_corim = vec![0; metadata.len() as usize];
        f.read(&mut psa_corim).expect("buffer overflow");
        let client = reqwest::blocking::ClientBuilder::new()
            .timeout(None)
            .build()
            .map_err(|err| panic!("Unable to build client to post Nitro CORIM:{:?}", err)).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/corim-unsigned+cbor; profile=http://aws.com/nitro"));
        let response = client.post("http://127.0.0.1:8888/endorsement-provisioning/v1/submit")
            .headers(headers)
            .body(psa_corim)
            .send()
            .unwrap();
        if !response.status().is_success() {
            panic!("Failed to post Nitro CORIM to provisioning service. Status:{:?}", response.status());
        }
    });
}

