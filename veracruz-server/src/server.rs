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
use base64;
use policy_utils::policy::Policy;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

type EnclaveHandlerServer = Box<dyn crate::common::VeracruzServer + Sync + Send>;
type EnclaveHandler = Arc<Mutex<Option<EnclaveHandlerServer>>>;

fn veracruz_server_request(
    enclave_handler: EnclaveHandler,
    shutdown_tx: mpsc::UnboundedSender<()>,
    input_data: &str,
) -> Result<String, VeracruzServerError> {
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

        shutdown_tx.send(())?;
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

async fn handle_veracruz_server_request(
    enclave_handler: EnclaveHandler,
    shutdown_tx: mpsc::UnboundedSender<()>,
    mut stream: TcpStream,
) -> Result<(), VeracruzServerError> {
    let mut buf = vec![];
    stream.read_to_end(&mut buf).await?;
    let input_data = String::from_utf8(buf)?;
    let result = veracruz_server_request(enclave_handler, shutdown_tx, &input_data)?;
    stream.write_all(result.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn serve_veracruz_server_requests(
    veracruz_server_url: &str,
    enclave_handler: EnclaveHandler,
    shutdown_tx: mpsc::UnboundedSender<()>,
) -> Result<(), VeracruzServerError> {
    let listener = TcpListener::bind(veracruz_server_url).await?;
    loop {
        let (socket, _) = listener.accept().await?;
        let enclave_handler = enclave_handler.clone();
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = handle_veracruz_server_request(enclave_handler, shutdown_tx, socket).await;
        });
    }
}

/// A server that listens on one TCP port.
pub async fn server(policy_json: &str) -> Result<(), VeracruzServerError> {
    let policy: Policy = serde_json::from_str(policy_json)?;
    #[allow(non_snake_case)]
    let VERACRUZ_SERVER: EnclaveHandler = Arc::new(Mutex::new(Some(Box::new(
        VeracruzServerEnclave::new(policy_json)?,
    ))));

    // create a channel for stopping the server
    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

    tokio::select! {
        x = serve_veracruz_server_requests(&policy.veracruz_server_url(), VERACRUZ_SERVER.clone(), shutdown_tx.clone()) => x,
        _ = async { shutdown_rx.recv().await } => Ok(()),
    }
}
