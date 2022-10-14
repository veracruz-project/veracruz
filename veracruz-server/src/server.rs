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

use crate::common::*;
#[cfg(feature = "icecap")]
use crate::platforms::icecap::VeracruzServerIceCap as VeracruzServerEnclave;
#[cfg(feature = "linux")]
use crate::platforms::linux::veracruz_server_linux::VeracruzServerLinux as VeracruzServerEnclave;
#[cfg(feature = "nitro")]
use crate::platforms::nitro::veracruz_server_nitro::VeracruzServerNitro as VeracruzServerEnclave;
use actix_web::{dev::Server, middleware, post, web, App, HttpRequest, HttpServer};
use base64;
use futures::executor;
use policy_utils::policy::Policy;
use std::{
    sync::mpsc,
    sync::{Arc, Mutex},
    thread,
};

type EnclaveHandlerServer = Box<dyn crate::common::VeracruzServer + Sync + Send>;
type EnclaveHandler = Arc<Mutex<Option<EnclaveHandlerServer>>>;

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

        // Drop the `VeracruzServer` object which triggers enclave shutdown
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
        VeracruzServerEnclave::new(policy_json)?,
    ))));

    // create a channel for stop server
    let (shutdown_channel_tx, shutdown_channel_rx) = mpsc::channel::<()>();

    let server = HttpServer::new(move || {
        // give the server a Sender in .data
        App::new()
            // pass in the shutdown channel and enclave handler VERACRUZ_SERVER to the server
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(shutdown_channel_tx.clone()))
            .app_data(web::Data::new(VERACRUZ_SERVER.clone()))
            .service(runtime_manager_request)
    })
    .bind(&policy.veracruz_server_url())?
    .run();

    // Get the Server handle and pass it to the thread for shutting down the server
    let handle = server.handle();
    thread::spawn(move || {
        // wait for shutdown signal and stop the server gracefully
        if shutdown_channel_rx.recv().is_ok() {
            executor::block_on(handle.stop(true));
        }
    });
    Ok(server)
}
