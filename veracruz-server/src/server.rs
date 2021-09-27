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

use actix_web::{dev::Server, get, middleware, post, web, App, HttpRequest, HttpServer, Responder};
use base64;
use futures::executor;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::TryFrom,
    num::ParseIntError,
    sync::mpsc,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};
use veracruz_utils::policy::policy::Policy;

type EnclaveHandlerServer = Box<dyn crate::veracruz_server::VeracruzServer + Sync + Send>;
type EnclaveHandler = Arc<Mutex<Option<EnclaveHandlerServer>>>;


//type EnclaveList = Arc<Mutex<Vec<Option<EnclaveState>>>>;

struct EnclaveState {
    enclave: Box<dyn VeracruzServer + Send>,
    start_time: SystemTime,
    policy: String,
    policy_hash: String,
}

lazy_static! {
    /// A list of active enclaves, mapping id -> enclaves, policy, and starttime
    ///
    static ref ACTIVE_ENCLAVES: Mutex<Vec<Option<EnclaveState>>> = {
        Mutex::new(Vec::new())
    };
}

/// Parse optional id
///
/// Since we always use the first available slot, we can default to
/// the id 0 for systems where only a single enclave is supported
///
/// To do this with actix, we need to use a "tail match" and parse
/// out the optional id ourselves
///
fn parse_optional_id(id_path: &str) -> Result<u32, ParseIntError> {
    if id_path.len() == 0 {
        Ok(0)
    } else if id_path.starts_with('/') {
        // expect leading slash
        id_path[1..].parse::<u32>()
    } else {
        // force ParseIntError
        "".parse::<u32>()
    }
}

//#[post("/enclave_setup")]
//async fn enclave_setup(
//    
//) -> VeracruzServerResponder

#[post("/enclave_setup")]
async fn enclave_setup(
    policy_json: String,
) -> Result<String, VeracruzServerError> {
    // parse policy
    let policy = serde_json::from_str::<Policy>(&policy_json)?;
    let policy_hash = policy.policy_hash().unwrap();

    // find next enclave slot
    let mut active_enclaves = ACTIVE_ENCLAVES.lock()?;
    let id = match active_enclaves.iter().position(|e| e.is_none()) {
        Some(id) => id,
        None => {
            // allocate new slot
            active_enclaves.push(None);
            active_enclaves.len()-1
        }
    };

    // setup enclave instance
    // TODO prevent multiple enclaves when not possible
    let enclave = VeracruzServerEnclave::new(&policy_json)?;

    // store enclave in list
    active_enclaves[id] = Some(EnclaveState {
        enclave: Box::new(enclave),
        start_time: SystemTime::now(),
        policy: policy_json,
        policy_hash: policy_hash.to_owned(),
    });

    // return the current id
    Ok(serde_json::to_string(&id)?)
}

#[post("/enclave_teardown{id:.*}")]
async fn enclave_teardown(
    web::Path((id)): web::Path<String>,
) -> Result<String, VeracruzServerError> {
    let id = parse_optional_id(&id)?;
    let mut active_enclaves = ACTIVE_ENCLAVES.lock()?;

    // does enclave exist?
    match active_enclaves.get_mut(usize::try_from(id).unwrap()) {
        Some(state) if state.is_some() => {
            // remove instance, let drop take care of the rest
            *state = None;
            Ok("".to_owned())
        }
        _ => Err(VeracruzServerError::InvalidEnclaveIdError(id)),
    }
}

/// Representation of an enclave in enclave_list
#[derive(Debug, Deserialize, Serialize)]
struct EnclaveListEntry {
    id: u32,
    policy_hash: String,
    uptime: Duration,
}

#[get("/enclave_list")]
async fn enclave_list() -> Result<String, VeracruzServerError> {
    let active_enclaves = ACTIVE_ENCLAVES.lock()?;

    let mut list = Vec::with_capacity(active_enclaves.len());
    for (id, state) in active_enclaves.iter().enumerate() {
        if let Some(state) = state {
            // SystemTime can error if time has moved backwards,
            // if this happens (clock change?) we just show an uptime of zero
            let uptime = state.start_time.elapsed()
                .unwrap_or_else(|_| Duration::from_secs(0));

            list.push(EnclaveListEntry {
                id: u32::try_from(id).unwrap(),
                policy_hash: state.policy_hash.clone(),
                uptime: uptime,
            });
        }
    }

    // note we can't return a web::Json object here because Actix and Veracruz
    // are actually using two incompatible versions of serde at the moment
    Ok(serde_json::to_string(&list)?)
}

#[get("/enclave_policy{id:.*}")]
async fn enclave_policy(
    web::Path((id)): web::Path<String>,
) -> Result<String, VeracruzServerError> {
    let id = parse_optional_id(&id)?;
    let active_enclaves = ACTIVE_ENCLAVES.lock()?;

    // does enclave exist?
    let state = active_enclaves.get(usize::try_from(id).unwrap())
        .map(|o| o.as_ref())
        .flatten()
        .ok_or_else(|| VeracruzServerError::InvalidEnclaveIdError(id))?;

    Ok(state.policy.clone())
}

#[post("/enclave_tls{id:.*)")]
async fn enclave_tls(
    web::Path((id)): web::Path<String>,
    input_data: String,
) -> Result<String, VeracruzServerError> {
    // parse out instance id
    let id = parse_optional_id(&id)?;

    // parse out session id / tls data
    let fields = input_data.split_whitespace().collect::<Vec<&str>>();
    if fields.len() < 2 {
        return Err(VeracruzServerError::InvalidRequestFormatError);
    }

    let session_id = match fields[0].parse::<u32>()? {
        0 => None,
        n @ 1u32..=std::u32::MAX => Some(n),
    };

    let received_data = base64::decode(&fields[1])?;

    // does enclave exist?
    let mut active_enclaves = ACTIVE_ENCLAVES.lock()?;
    let mut state = active_enclaves.get_mut(usize::try_from(id).unwrap())
        .map(|o| o.as_mut())
        .flatten()
        .ok_or_else(|| VeracruzServerError::InvalidEnclaveIdError(id))?;

    // needs a new TLS session?
    let session_id = match session_id {
        Some(id) => id,
        None => {
            state.enclave.new_tls_session()?
        }
    };

    // send data to enclave
    let (active_flag, output_data_option)
        = state.enclave.tls_data(session_id, received_data)?;

    // shutdown the enclave
    if !active_flag {
        // TODO does this work?
        // leave it up to drop to clean up resources
        active_enclaves[usize::try_from(id).unwrap()] = None;
    }

    // response this request
    Ok(match output_data_option {
        None => String::new(),
        Some(output_data) => {
            let output_data_formatted = output_data
                .iter()
                .map(|item| base64::encode(&item))
                .collect::<Vec<String>>()
                .join(" ");
            format!("{:} {}", session_id, output_data_formatted)
        }
    })
}





#[post("/veracruz_server")]
#[deprecated]
async fn veracruz_server_request(
    enclave_handler: web::Data<EnclaveHandler>,
    _request: HttpRequest,
    input_data: String,
) -> VeracruzServerResponder {
    let input_data_decoded = base64::decode(&input_data)?;

    panic!("this should be currently unused");
    
    let mut enclave_handler_locked = enclave_handler.lock()?;

    let enclave = enclave_handler_locked.as_mut().ok_or(VeracruzServerError::UninitializedEnclaveError)?;

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

            let enclave = enclave_handler_locked.as_mut().ok_or(VeracruzServerError::UninitializedEnclaveError)?;

            enclave.new_tls_session()?
        }    
        n @ 1u32..=std::u32::MAX => n,
    };

    let received_data = fields[1];
    let received_data_decoded = base64::decode(&received_data)?;

    let (active_flag, output_data_option) = {
        let mut enclave_handler_locked = enclave_handler.lock()?;

        let enclave = enclave_handler_locked.as_mut().ok_or(VeracruzServerError::UninitializedEnclaveError)?;

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
    let VERACRUZ_SERVER: EnclaveHandler = Arc::new(Mutex::new(Some(Box::new(VeracruzServerEnclave::new(
        &policy_json,
    )?))));

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

            .service(enclave_setup)
            .service(enclave_teardown)
            .service(enclave_list)
            .service(enclave_policy)
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
