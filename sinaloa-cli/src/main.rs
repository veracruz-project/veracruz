//! Sinaloa command-line interface
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use structopt::StructOpt;
use std::path;
use env_logger;
use log::{info, warn, error};
use ring;
use hex;
use std::process;
use rand;
use rand::Rng;
use base64;
use curl::easy::{Easy, List};
use stringreader;
use std::io::Read;
use tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync;

use sinaloa::sinaloa::*;
#[cfg(feature = "sgx")]
use sinaloa::SinaloaSGX as SinaloaEnclave;
#[cfg(feature = "tz")]
use sinaloa::SinaloaTZ as SinaloaEnclave;


#[derive(Debug, StructOpt)]
#[structopt(
    name="sinaloa",
    about="Command-line interface for Sinaloa, \
        the REST-server frontend for Veracruz.",
    rename_all="kebab"
)]
struct Opt {
    /// Path to policy file
    #[structopt(parse(from_os_str))]
    policy_path: path::PathBuf,

    /// Buffer size for network connections
    #[structopt(long, default_value="1024")]
    buffer_size: usize,

    /// Disable attestation flow, does not register attestation token
    /// with Tabasco. This means the server will not be able to attest that
    /// the enclave is trusted.
    #[structopt(long)]
    no_attestation: bool,
}


// send POST request
fn post_buffer(url: &str, data: &str) -> Result<String, SinaloaError> {
    let mut data_reader = stringreader::StringReader::new(&data);
    let mut curl_request = Easy::new();
    curl_request.url(url)?;

    let mut headers = List::new();
    headers.append("Content-Type: application/octet-stream")?;

    curl_request.http_headers(headers)?;

    curl_request.post(true)?;
    curl_request.post_field_size(data.len() as u64)?;
    curl_request.fail_on_error(true)?;

    let mut received_body = std::string::String::new();
    let mut received_header = std::string::String::new();
    {
        let mut transfer = curl_request.transfer();

        transfer.read_function(|buf| Ok(data_reader.read(buf).unwrap_or(0)))?;

        transfer.write_function(|buf| {
            received_body.push_str(
                std::str::from_utf8(buf)
                    .expect(&format!("Error converting data {:?} from UTF-8", buf)),
            );
            Ok(buf.len())
        })?;
        transfer.header_function(|buf| {
            received_header.push_str(
                std::str::from_utf8(buf)
                    .expect(&format!("Error converting data {:?} from UTF-8", buf)),
            );
            true
        })?;

        transfer.perform()?;
    }

    let header_lines: Vec<&str> = {
        let lines = received_header.split("\n");
        lines.collect()
    };
    let mut header_fields = std::collections::HashMap::new();
    for this_line in header_lines.iter() {
        let fields: Vec<&str> = this_line.split(":").collect();
        if fields.len() == 2 {
            header_fields.insert(fields[0], fields[1]);
        }
    }
    Ok(received_body)
}

// perform attestation via Tabasco server
fn attestation_flow(
    tabasco_url: &str,
    expected_enclave_hash: &str,
    sinaloa: &dyn sinaloa::Sinaloa,
) -> Result<Vec<u8>, SinaloaError> {
    let challenge = rand::thread_rng().gen::<[u8; 32]>();
    info!("Attestation challenge {}", hex::encode(&challenge));

    let serialized_pagt = colima::serialize_request_proxy_psa_attestation_token(&challenge)?;
    let pagt_ret = sinaloa.plaintext_data(serialized_pagt)?;
    let received_bytes =
        pagt_ret.ok_or(SinaloaError::MissingFieldError("attestation_flow pagt_ret"))?;

    let encoded_token = base64::encode(&received_bytes);
    let complete_tabasco_url = format!("{}/VerifyPAT", tabasco_url);
    let received_buffer = post_buffer(&complete_tabasco_url, &encoded_token)?;

    let received_payload = base64::decode(&received_buffer)?;

    if challenge != received_payload[8..40] {
        return Err(SinaloaError::MismatchError {
            variable: "attestation_flow challenge",
            received: received_payload[8..40].to_vec(),
            expected: challenge.to_vec(),
        });
    }
    let hash_bin = hex::decode(expected_enclave_hash)?;
    if hash_bin != received_payload[47..79].to_vec() {
        return Err(SinaloaError::MismatchError {
            variable: "attestation_flow challenge",
            received: received_payload[47..79].to_vec(),
            expected: hash_bin.to_vec(),
        });
    }

    let enclave_cert_hash = received_payload[86..118].to_vec();
    Ok(enclave_cert_hash)
}

/// Entry point
#[tokio::main]
async fn main() {
    // parse args
    let opt = Opt::from_args();

    // setup logger
    env_logger::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    // load policy
    info!("Loading policy {:?}", opt.policy_path);
    let policy_json = match std::fs::read_to_string(&opt.policy_path) {
        Ok(policy_json) => policy_json,
        Err(_) => {
            error!("Cannot open file {:?}", opt.policy_path);
            process::exit(1);
        }
    };
    let policy_hash_bytes = ring::digest::digest(
        &ring::digest::SHA256, policy_json.as_bytes());
    let policy_hash = hex::encode(&policy_hash_bytes.as_ref().to_vec());
    let policy = match veracruz_utils::VeracruzPolicy::from_json(
            policy_json.as_str()) {
        Ok(policy) => policy,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Loaded policy {}", policy_hash);

    // create Sinaloa instance
    let sinaloa = match SinaloaEnclave::new(&policy_json) {
        Ok(policy) => policy,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };

    // attest via Tabasco?
    let enclave_cert_hash;
    if !opt.no_attestation {
        enclave_cert_hash = match attestation_flow(
                &policy.tabasco_url(),
                &policy.mexico_city_hash(),
                &sinaloa) {
            Ok(enclave_cert_hash) => enclave_cert_hash,
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        };
        info!("Successfully attested enclave");
        info!("Enclave certificate hash {}", hex::encode(&enclave_cert_hash));
    } else {
        match sinaloa.get_enclave_cert() {
            Ok(enclave_cert) => {
                enclave_cert_hash = ring::digest::digest(
                        &ring::digest::SHA256,
                        enclave_cert.as_ref()
                    )
                    .as_ref()
                    .to_vec();
            }
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        }
        warn!("Skipping enclave attestation");
        info!("Enclave certificate hash {}", hex::encode(&enclave_cert_hash));
    }

    // create TCP server, we're just providing a tunnel for the TLS
    // connection, so nothing special here
    let listener = match tokio::net::TcpListener::bind(
        policy.sinaloa_url()
    ).await {
        Ok(listener) => listener,
        Err(err) => {
            error!("{}", err);
            process::exit(1);
        }
    };
    info!("Sinaloa running on {}", policy.sinaloa_url());

    // allow sharing across threads
    let sinaloa_arc = sync::Arc::new(sinaloa);

    loop {
        let (mut socket, client_addr) = match listener.accept().await {
            Ok(client) => client,
            Err(err) => {
                error!("{}", err);
                process::exit(1);
            }
        };

        info!("Client {} connected", client_addr);
        let sinaloa_ref = sync::Arc::clone(&sinaloa_arc);
        let buffer_size = opt.buffer_size;
        tokio::spawn(async move {
            let mut buffer = vec![0; buffer_size];

            // Create new Sinaloa session
            let session_id = match sinaloa_ref.new_tls_session() {
                Ok(session_id) if session_id != 0 => session_id,
                Ok(_) => {
                    error!("Failed to create Sinaloa session");
                    return;
                }
                Err(err) => {
                    error!("{}", err);
                    return;
                }
            };
            info!("Client {} session id {}", client_addr, session_id);

            loop {
                let size = match socket.read(&mut buffer).await {
                    Ok(size) if size > 0 => size,
                    Ok(_) => {
                        // socket closed gracefully
                        break;
                    }
                    Err(err) => {
                        error!("{}", err);
                        return;
                    }
                };

                // Forward to Sinaloa
                // TODO this should take a slice
                let (active, response) = match sinaloa_ref.tls_data(
                    session_id,
                    Vec::from(&buffer[..size])
                ) {
                    Ok((active, response)) => (active, response),
                    Err(err) => {
                        error!("{}", err);
                        return;
                    }
                };

                if let Some(buffers) = response {
                    for buffer in buffers {
                        if let Err(err) = socket.write_all(&buffer).await {
                            error!("{}", err);
                            return;
                        }
                    }
                }

                if !active {
                    break;
                }
            }

            info!("Client {} disconnected", client_addr);
        });
    }
}
