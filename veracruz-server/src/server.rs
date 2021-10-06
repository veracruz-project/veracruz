//! The Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::veracruz_server::*;
#[cfg(feature = "nitro")]
use crate::veracruz_server_nitro::veracruz_server_nitro::VeracruzServerNitro as VeracruzServerEnclave;
#[cfg(feature = "sgx")]
use crate::veracruz_server_sgx::veracruz_server_sgx::VeracruzServerSGX as VeracruzServerEnclave;
#[cfg(feature = "tz")]
use crate::veracruz_server_tz::veracruz_server_tz::VeracruzServerTZ as VeracruzServerEnclave;

use actix_web::{dev::Server, get, middleware, post, web, App, HttpServer};
use base64;
use futures::executor;
use std::{
    net::ToSocketAddrs,
    sync::mpsc,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};
use veracruz_utils::policy::policy::Policy;


/// State of a running enclave, this is a bit of additional state the server
/// can keep track of to simplify the VeracruzServer trait
struct EnclaveState {
    enclave: Box<dyn VeracruzServer>,
    start_time: SystemTime,
    policy: String,
    policy_hash: String,
}

/// Type alias of a thread-safe, optional EnclaveState
type EnclaveHandler = Arc<Mutex<Option<EnclaveState>>>;


/// Setup an enclave with a provided policy file
#[post("/enclave_setup")]
async fn enclave_setup(
    policy_json: String,
    enclave_handler: web::Data<EnclaveHandler>,
) -> Result<String, VeracruzServerError> {
    // parse policy
    let policy = Policy::from_json(&policy_json)?;
    let policy_hash = policy.policy_hash().unwrap();

    // check that we don't already have an enclave running
    let mut enclave_handler = enclave_handler.lock()?;
    if !enclave_handler.is_none() {
        Err(VeracruzServerError::TooManyEnclavesError(2, 1))?
    }

    // create new enclave, with policy
    let enclave = VeracruzServerEnclave::new(&policy_json)?;
    *enclave_handler = Some(EnclaveState {
        enclave: Box::new(enclave),
        start_time: SystemTime::now(),
        policy: policy_json,
        policy_hash: policy_hash.to_owned(),
    });

    // return 0, this may be the current id in the future
    Ok(serde_json::to_string(&0)?)
}

/// Teardown an enclave
#[post("/enclave_teardown")]
async fn enclave_teardown(
    enclave_handler: web::Data<EnclaveHandler>,
) -> Result<String, VeracruzServerError> {
    // does enclave exist?
    let mut enclave_handler = enclave_handler.lock()?;
    match enclave_handler.take() {
        Some(_enclave) => {
            // well it doesn't anymore, let drop take care of the rest
            Ok("".to_owned())
        }
        None => {
            Err(VeracruzServerError::UninitializedEnclaveError)?
        }
    }
}

/// Query a list of running enclaves
///
/// Currently this can only be one or zero enclaves
///
#[get("/enclave_list")]
async fn enclave_list(
    enclave_handler: web::Data<EnclaveHandler>,
) -> Result<String, VeracruzServerError> {
    let mut enclave_list = Vec::<serde_json::Value>::new();
    
    let enclave_handler = enclave_handler.lock()?;
    match enclave_handler.as_ref() {
        Some(enclave) => {
            // Apparently SystemTime can error if time has moved backwards,
            // if this happens (clock change?) we just show an uptime of zero
            let uptime = enclave.start_time.elapsed()
                .unwrap_or_else(|_| Duration::from_secs(0));

            // note we can't return a web::Json object here because Actix and Veracruz
            // are actually using two incompatible versions of serde at the moment
            enclave_list.push(serde_json::json!({
                "policy_hash": enclave.policy_hash,
                "id": 0,
                "uptime": uptime,
            }));
        }
        None => {
            // Note! This is not an error! The client may just want to be
            // querying what enclaves exist
        }
    };

    // note we can't return a web::Json object here because Actix and Veracruz
    // are actually using two incompatible versions of serde at the moment
    Ok(serde_json::to_string(&enclave_list)?)
}

/// Get the policy governing an enclave's computation
#[get("/enclave_policy")]
async fn enclave_policy(
    enclave_handler: web::Data<EnclaveHandler>,
) -> Result<String, VeracruzServerError> {
    // does enclave exist?
    let enclave_handler = enclave_handler.lock()?;
    let enclave = match enclave_handler.as_ref() {
        Some(enclave) => enclave,
        None => {
            Err(VeracruzServerError::UninitializedEnclaveError)?
        }
    };

    Ok(enclave.policy.clone())
}

/// Send TLS data to a currently running enclave
#[post("/enclave_tls")]
async fn enclave_tls(
    enclave_handler: web::Data<EnclaveHandler>,
    stopper: web::Data<mpsc::Sender<()>>,
    //_request: HttpRequest,
    input_data: String,
) -> VeracruzServerResponder {
    let fields = input_data.split_whitespace().collect::<Vec<&str>>();
    if fields.len() < 2 {
        return Err(VeracruzServerError::InvalidRequestFormatError);
    }
    let session_id = match fields[0].parse::<u32>()? {
        0 => {
            let mut enclave_handler_locked = enclave_handler.lock()?;

            let enclave = enclave_handler_locked.as_mut().ok_or(VeracruzServerError::UninitializedEnclaveError)?;

            enclave.enclave.new_tls_session()?
        }    
        n @ 1u32..=std::u32::MAX => n,
    };

    let received_data = fields[1];
    let received_data_decoded = base64::decode(&received_data)?;

    let (active_flag, output_data_option) = {
        let mut enclave_handler_locked = enclave_handler.lock()?;

        let enclave = enclave_handler_locked.as_mut().ok_or(VeracruzServerError::UninitializedEnclaveError)?;

        enclave.enclave.tls_data(session_id, received_data_decoded)?
    };

    // Shutdown the enclave
    // TODO this?
    if !active_flag {
        let mut enclave_handler_locked = enclave_handler.lock()?;
        enclave_handler_locked.as_mut().map(|e| e.enclave.close());
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
///
/// If a policy is provided the server will be started with an enclave setup with
/// the given policy, otherwise the policy can be sent over an `enclave_setup`
/// request.
///
pub fn server<U>(url: U, policy_json: Option<&str>) -> Result<Server, VeracruzServerError>
where
    U: ToSocketAddrs
{
    // create an enclave if policy was provided, otherwise leave this up to enclave_setup
    let enclave_handler: EnclaveHandler = Arc::new(Mutex::new(
        match policy_json {
            Some(policy_json) => {
                // parse policy
                let policy = Policy::from_json(&policy_json)?;
                let policy_hash = policy.policy_hash().unwrap();

                // create enclave
                let enclave = VeracruzServerEnclave::new(&policy_json)?;
                Some(EnclaveState {
                    enclave: Box::new(enclave),
                    start_time: SystemTime::now(),
                    policy: policy_json.to_owned(),
                    policy_hash: policy_hash.to_owned(),
                })
            }
            None => None,
        }
    ));

    // create a channel for stop server
    let (shutdown_channel_tx, shutdown_channel_rx) = mpsc::channel::<()>();

    let server = HttpServer::new(move || {
        // create an enclave if policy was provided, otherwise leave

        // give the server a Sender in .data
        App::new()
            // enable logging
            .wrap(middleware::Logger::default())
            // provide enclave handler, an Option<EnclaveHandler> which may change
            // between None or Some through the server's lifetime
            .data(enclave_handler.clone())
            // also the shutdown channel
            .data(shutdown_channel_tx.clone())

            .service(enclave_setup)
            .service(enclave_teardown)
            .service(enclave_list)
            .service(enclave_policy)
            .service(enclave_tls)
    })
    .bind(url)?
    .run();

    // clone the Server handle and launch a thread for shuting down the server
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

