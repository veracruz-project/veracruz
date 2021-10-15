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
    collections::HashMap,
    net::ToSocketAddrs,
    num::ParseIntError,
    sync::{Arc, Mutex, mpsc},
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

/// State of enclaves
struct EnclaveHandler {
    enclaves: HashMap<u32, EnclaveState>,
    id_gen: Box<dyn Iterator<Item=u32> + Send>,
    auto_shutdown_tx: Option<mpsc::Sender<()>>,
}

impl EnclaveHandler {
    /// Parse optional id
    ///
    /// To do this with actix, we need to use a "tail match" and parse
    /// out the optional id ourselves
    ///
    fn parse_optional_id(
        &self,
        id_path: &str
    ) -> Result<u32, ParseIntError> {
        if id_path.len() == 0 {
            // If we don't have an id, lookup what the id should
            // be. If there are no enclaves at all, return 0 (an invalid id)
            // and let the handler error when they look it up.
            Ok(self.enclaves.iter().next().map(|(id, _)| *id).unwrap_or(0))
        } else if id_path.starts_with('/') {
            // expect leading slash
            id_path[1..].parse::<u32>()
        } else {
            // force ParseIntError
            "".parse::<u32>()
        }
    }
}


/// Setup an enclave with a provided policy file
#[post("/enclave_setup")]
async fn enclave_setup(
    policy_json: String,
    enclave_handler: web::Data<Arc<Mutex<EnclaveHandler>>>,
) -> Result<String, VeracruzServerError> {
    // parse policy
    let policy = Policy::from_json(&policy_json)?;
    let policy_hash = policy.policy_hash().unwrap();

    // create new enclave, with policy
    let enclave = VeracruzServerEnclave::new(&policy_json)?;

    // find next id
    let mut enclave_handler = enclave_handler.lock()?;
    let id = enclave_handler.id_gen.next().unwrap();

    // store id in list
    enclave_handler.enclaves.insert(id, EnclaveState {
        enclave: Box::new(enclave),
        start_time: SystemTime::now(),
        policy: policy_json,
        policy_hash: policy_hash.to_owned(),
    });

    Ok(serde_json::to_string(&id)?)
}

/// Teardown an enclave
#[post("/enclave_teardown{id:.*}")]
async fn enclave_teardown(
    web::Path(id): web::Path<String>,
    enclave_handler: web::Data<Arc<Mutex<EnclaveHandler>>>,
) -> Result<String, VeracruzServerError> {
    // does enclave exist?
    let mut enclave_handler = enclave_handler.lock()?;
    let id = enclave_handler.parse_optional_id(&id)?;
    match enclave_handler.enclaves.remove(&id) {
        Some(mut enclave) => {
            // well it doesn't anymore, let close take care of the rest
            enclave.enclave.close()?;
            Ok("".to_owned())
        }
        None => {
            Err(VeracruzServerError::InvalidEnclaveError(id))?
        }
    }
}

/// Query a list of running enclaves
///
/// Currently this can only be one or zero enclaves
///
#[get("/enclave_list")]
async fn enclave_list(
    enclave_handler: web::Data<Arc<Mutex<EnclaveHandler>>>,
) -> Result<String, VeracruzServerError> {
    let mut enclave_list = Vec::<serde_json::Value>::new();
    
    let enclave_handler = enclave_handler.lock()?;
    for (id, enclave) in enclave_handler.enclaves.iter() {
        // Apparently SystemTime can error if time has moved backwards,
        // if this happens (clock change?) we just show an uptime of zero
        let uptime = enclave.start_time.elapsed()
            .unwrap_or_else(|_| Duration::from_secs(0));

        // note we can't return a web::Json object here because Actix and Veracruz
        // are actually using two incompatible versions of serde at the moment
        enclave_list.push(serde_json::json!({
            "policy_hash": enclave.policy_hash,
            "id": id,
            "uptime": uptime,
        }));
    };

    // note we can't return a web::Json object here because Actix and Veracruz
    // are actually using two incompatible versions of serde at the moment
    Ok(serde_json::to_string(&enclave_list)?)
}

/// Get the policy governing an enclave's computation
#[get("/enclave_policy{id:.*}")]
async fn enclave_policy(
    web::Path(id): web::Path<String>,
    enclave_handler: web::Data<Arc<Mutex<EnclaveHandler>>>,
) -> Result<String, VeracruzServerError> {
    // does enclave exist?
    let enclave_handler = enclave_handler.lock()?;
    let id = enclave_handler.parse_optional_id(&id)?;
    let enclave = match enclave_handler.enclaves.get(&id) {
        Some(enclave) => enclave,
        None => {
            Err(VeracruzServerError::InvalidEnclaveError(id))?
        }
    };

    Ok(enclave.policy.clone())
}

/// Send TLS data to a currently running enclave
#[post("/enclave_tls{id:.*}")]
async fn enclave_tls(
    web::Path(id): web::Path<String>,
    enclave_handler: web::Data<Arc<Mutex<EnclaveHandler>>>,
    input_data: String,
) -> VeracruzServerResponder {
    let fields = input_data.split_whitespace().collect::<Vec<&str>>();
    if fields.len() < 2 {
        return Err(VeracruzServerError::InvalidRequestFormatError);
    }
    let session_id = match fields[0].parse::<u32>()? {
        0 => {
            let mut enclave_handler_locked = enclave_handler.lock()?;
            let id = enclave_handler_locked.parse_optional_id(&id)?;

            let enclave = enclave_handler_locked.enclaves.get_mut(&id).ok_or(VeracruzServerError::InvalidEnclaveError(id))?;

            enclave.enclave.new_tls_session()?
        }    
        n @ 1u32..=std::u32::MAX => n,
    };

    let received_data = fields[1];
    let received_data_decoded = base64::decode(&received_data)?;

    let (active_flag, output_data_option) = {
        let mut enclave_handler_locked = enclave_handler.lock()?;
        let id = enclave_handler_locked.parse_optional_id(&id)?;

        let enclave = enclave_handler_locked.enclaves.get_mut(&id).ok_or(VeracruzServerError::InvalidEnclaveError(id))?;

        enclave.enclave.tls_data(session_id, received_data_decoded)?
    };

    // Shutdown the enclave if we're done with it
    if !active_flag {
        let mut enclave_handler = enclave_handler.lock()?;
        let id = enclave_handler.parse_optional_id(&id)?;
        match enclave_handler.enclaves.remove(&id) {
            Some(mut enclave) => {
                // The enclave has been removed now, let drop take care of the rest
                enclave.enclave.close()?;

                // Auto-shutdown the server?
                if let Some(auto_shutdown_tx) = &enclave_handler.auto_shutdown_tx {
                    auto_shutdown_tx.send(())?;
                }
            }
            None => {
                Err(VeracruzServerError::InvalidEnclaveError(id))?
            }
        }
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
pub fn server<U>(
    url: U,
    policy_json: Option<&str>,
    auto_shutdown: bool,
) -> Result<Server, VeracruzServerError>
where
    U: ToSocketAddrs
{
    // create an enclave if policy was provided, otherwise leave this up to enclave_setup
    let enclave_state = match policy_json {
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
    };

    let mut id_gen = 1..;

    let (auto_shutdown_tx, auto_shutdown_rx) = if auto_shutdown {
        let (auto_shutdown_tx, auto_shutdown_rx) = mpsc::channel::<()>();
        (Some(auto_shutdown_tx), Some(auto_shutdown_rx))
    } else {
        (None, None)
    };

    let enclave_handler = Arc::new(Mutex::new(EnclaveHandler {
        enclaves: enclave_state.into_iter()
            .map(|enclave_state| (id_gen.next().unwrap(), enclave_state))
            .collect(),
        id_gen: Box::new(id_gen),
        auto_shutdown_tx: auto_shutdown_tx,
    }));

    let server = HttpServer::new(move || {
        // create an enclave if policy was provided, otherwise leave

        // give the server a Sender in .data
        App::new()
            // enable logging
            .wrap(middleware::Logger::default())

            // provide enclave handler, an Option<EnclaveHandler> which may change
            // between None or Some through the server's lifetime
            .data(enclave_handler.clone())

            .service(enclave_setup)
            .service(enclave_teardown)
            .service(enclave_list)
            .service(enclave_policy)
            .service(enclave_tls)
    })
    .bind(url)?
    .run();

    // launch a thread for shutting down the server?
    if let Some(auto_shutdown_rx) = auto_shutdown_rx {
        let server_clone = server.clone();
        thread::spawn(move || {
            // wait for shutdown signal
            match auto_shutdown_rx.recv() {
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
    }

    Ok(server)
}

