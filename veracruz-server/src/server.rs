//! The Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::veracruz_server::*;
#[cfg(feature = "icecap")]
use crate::veracruz_server_icecap::VeracruzServerIceCap as VeracruzServerEnclave;
#[cfg(feature = "linux")]
use crate::veracruz_server_linux::veracruz_server_linux::VeracruzServerLinux as VeracruzServerEnclave;
#[cfg(feature = "nitro")]
use crate::veracruz_server_nitro::veracruz_server_nitro::VeracruzServerNitro as VeracruzServerEnclave;

use actix_web::{dev::Server, middleware, post, web, App, HttpRequest, HttpServer};
use base64;
use futures::executor;
use policy_utils::policy::Policy;
use std::{
    sync::mpsc,
    sync::{Arc, Mutex},
    thread,
};

type EnclaveHandlerServer = Box<dyn crate::veracruz_server::VeracruzServer + Sync + Send>;
type EnclaveHandler = Arc<Mutex<Option<EnclaveHandlerServer>>>;

#[post("/veracruz_server")]
async fn veracruz_server_request(
    enclave_handler: web::Data<EnclaveHandler>,
    _request: HttpRequest,
    input_data: String,
) -> VeracruzServerResponder {
    let input_data_decoded = base64::decode(&input_data)?;

    let mut enclave_handler_locked = enclave_handler.lock()?;

    let enclave = enclave_handler_locked
        .as_mut()
        .ok_or(VeracruzServerError::UninitializedEnclaveError)?;

    let result = enclave.plaintext_data(input_data_decoded)?;

    let result_string = match result {
        Some(return_data) => base64::encode(&return_data),
        None => String::new(),
    };

    Ok(result_string)
}

#[post("/runtime_manager")]
async fn runtime_manager_request(
    enclave_handler: web::Data<EnclaveHandler>,
    stopper: web::Data<mpsc::Sender<()>>,
    _request: HttpRequest,
    input_data: String,
) -> VeracruzServerResponder {
    let fields = input_data.split_whitespace().collect::<Vec<&str>>();
    if fields.len() < 2 {
        return Err(VeracruzServerError::InvalidRequestFormatError);
    }
    let session_id = match fields[0].parse::<u32>()? {
        0 => {
            let mut enclave_handler_locked = enclave_handler.lock()?;

            let enclave = enclave_handler_locked
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?;

            enclave.new_tls_session()?
        }
        n @ 1u32..=std::u32::MAX => n,
    };

    let received_data = fields[1];
    let received_data_decoded = base64::decode(&received_data)?;

    let (active_flag, output_data_option) = {
        let mut enclave_handler_locked = enclave_handler.lock()?;

        let enclave = enclave_handler_locked
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?;

        enclave.tls_data(session_id, received_data_decoded)?
    };

    // Shutdown the enclave
    if !active_flag {
        let mut enclave_handler_locked = enclave_handler.lock()?;
        enclave_handler_locked.as_mut().map(|e| e.close());
        *enclave_handler_locked = None;
        stopper.send(())?;
    }

    // Response this request
    let result = match output_data_option {
        None => String::new(),
        Some(output_data) => {
            let output_data_formatted = output_data
                .iter()
                .map(|item| base64::encode(&item))
                .collect::<Vec<String>>()
                .join(" ");
            format!("{:} {}", session_id, output_data_formatted)
        }
    };
    Ok(result)
}

/// Return an actix server. The caller should call .await for starting the service.
pub fn server(policy_json: &str) -> Result<Server, VeracruzServerError> {
    let policy: Policy = serde_json::from_str(policy_json)?;
    #[allow(non_snake_case)]
    let VERACRUZ_SERVER: EnclaveHandler = Arc::new(Mutex::new(Some(Box::new(
        VeracruzServerEnclave::new(&policy_json)?,
    ))));

    // create a channel for stop server
    let (shutdown_channel_tx, shutdown_channel_rx) = mpsc::channel::<()>();

    let server = HttpServer::new(move || {
        // give the server a Sender in .data
        App::new()
            // pass in the shutdown channel and enclave handler VERACRUZ_SERVER to the server
            .wrap(middleware::Logger::default())
            .data(shutdown_channel_tx.clone())
            .data(VERACRUZ_SERVER.clone())
            .service(veracruz_server_request)
            .service(runtime_manager_request)
    })
    .bind(&policy.veracruz_server_url())?
    .run();

    // clone the Server handle and pass the the thread for shuting down the server
    let server_clone = server.clone();
    thread::spawn(move || {
        // wait for shutdown signal
        match shutdown_channel_rx.recv() {
            // stop server gracefully
            Ok(_) => {
                executor::block_on(server_clone.stop(true));
            }
            // this CAN fail, in the case that the main thread has died,
            // most likely from a user's ctrl-C, in either case we want to
            // shutdown the server
            Err(_) => {
                return;
            }
        }
    });
    Ok(server)
}
