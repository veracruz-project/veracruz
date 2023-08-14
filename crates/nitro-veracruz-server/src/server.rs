//! Nitro-Enclave-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use bincode;
use log::info;
use nitro_enclave::NitroEnclave;
use policy_utils::policy::Policy;
use proxy_attestation_client;
use std::{env, error::Error};
use veracruz_server::{VeracruzServer, VeracruzServerError};
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};

/// Path of the Runtime Manager enclave EIF file.
const RUNTIME_MANAGER_EIF_PATH: &str = "../nitro-runtime-manager/runtime_manager.eif";

/// The port to use for communicating with the Veracruz Nitro enclave
const VERACRUZ_NITRO_PORT: u32 = 5005;

pub struct VeracruzServerNitro {
    enclave: NitroEnclave,
}

impl VeracruzServer for VeracruzServerNitro {
    fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
        // Set up, initialize Nitro Root Enclave
        let policy: Policy = Policy::from_json(policy_json)?;

        let (challenge_id, challenge) = proxy_attestation_client::start_proxy_attestation(
            policy.proxy_attestation_server_url(),
        )
        .map_err(|e| {
            eprintln!(
                "Failed to start proxy attestation process.  Error produced: {}.",
                e
            );

            e
        })?;

        info!("VeracruzServerNitro::new instantiating Runtime Manager");
        let runtime_manager_eif_path = env::var("RUNTIME_MANAGER_EIF_PATH")
            .unwrap_or_else(|_| RUNTIME_MANAGER_EIF_PATH.to_string());
        #[cfg(feature = "debug")]
        let runtime_manager_enclave = {
            println!("Starting Runtime Manager enclave in debug mode");
            NitroEnclave::new(
                &runtime_manager_eif_path,
                true,
                *policy.max_memory_mib(),
                VERACRUZ_NITRO_PORT,
            )?
        };
        #[cfg(not(feature = "debug"))]
        let runtime_manager_enclave = {
            println!("Starting Runtime Manager enclave in release mode");
            NitroEnclave::new(
                &runtime_manager_eif_path,
                false,
                *policy.max_memory_mib(),
                VERACRUZ_NITRO_PORT,
            )?
        };
        println!("VeracruzServerNitro::new NitroEnclave::new returned");
        let meta = Self {
            enclave: runtime_manager_enclave,
        };
        println!("VeracruzServerNitro::new Runtime Manager instantiated. Calling initialize");

        let (attestation_doc, csr) = {
            let attestation = RuntimeManagerRequest::Attestation(challenge, challenge_id);
            meta.enclave
                .send_buffer(&bincode::serialize(&attestation)?)?;
            // read the response
            let response = meta.enclave.receive_buffer()?;
            match bincode::deserialize(&response[..])? {
                RuntimeManagerResponse::AttestationData(doc, csr) => (doc, csr),
                response_message => {
                    return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        response_message,
                    ))
                }
            }
        };

        let cert_chain = proxy_attestation_client::complete_proxy_attestation_nitro(
            policy.proxy_attestation_server_url(),
            &attestation_doc,
            &csr,
            challenge_id,
        )?;

        let initialize: RuntimeManagerRequest =
            RuntimeManagerRequest::Initialize(policy_json.to_string(), cert_chain);

        let encoded_buffer: Vec<u8> = bincode::serialize(&initialize)?;
        meta.enclave.send_buffer(&encoded_buffer)?;

        // read the response
        let status_buffer = meta.enclave.receive_buffer()?;

        let message: RuntimeManagerResponse = bincode::deserialize(&status_buffer[..])?;
        let status = match message {
            RuntimeManagerResponse::Status(status) => status,
            _ => return Err(VeracruzServerError::InvalidRuntimeManagerResponse(message)),
        };
        match status {
            Status::Success => (),
            _ => return Err(VeracruzServerError::Status(status)),
        }
        println!("VeracruzServerNitro::new complete. Returning");
        Ok(meta)
    }

    fn send_buffer(&mut self, buffer: &[u8]) -> Result<(), VeracruzServerError> {
        let ret = self.enclave.send_buffer(buffer)?;
        return Ok(ret);
    }

    fn receive_buffer(&mut self) -> Result<Vec<u8>, VeracruzServerError> {
        let ret = self.enclave.receive_buffer()?;
        return Ok(ret);
    }
}

impl Drop for VeracruzServerNitro {
    fn drop(&mut self) {
        if let Err(err) = self.shutdown_isolate() {
            println!(
                "VeracruzServerNitro::drop failed in call to self.shutdown_isolate:{:?}",
                err
            )
        }
    }
}

impl VeracruzServerNitro {
    fn shutdown_isolate(&mut self) -> Result<(), Box<dyn Error>> {
        // Don't do anything. The enclave gets shutdown when the
        // `NitroEnclave` object inside `VeracruzServerNitro` is dropped
        Ok(())
    }
}
