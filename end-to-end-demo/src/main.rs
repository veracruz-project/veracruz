//! End-to-end demo.
//!
//! A demo showing how to develop and deploy applications on-top of the Veracruz
//! framework.  Demonstrates provisioning secrets into the enclave via a secure
//! TLS link.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE.markdown` file in the Veracruz repository root directory
//! for licensing and copyright information.

use actix_rt::System;
use anyhow::Result;
use async_std::task;
use env_logger;
use log::{error, info};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{Display, Error, Formatter},
    fs::File,
    io::Read,
    path::Path,
    thread::{sleep, spawn},
    time::Duration,
};

use pinecone::from_bytes;
use proxy_attestation_server;
use std::io::stdin;
use std::process::exit;
use veracruz_client::VeracruzClient;
use veracruz_server;
use veracruz_utils::{platform::Platform, policy::policy::Policy};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// The path of the WASM binary that will be used for the collaborative
/// computation.
const WASM_BINARY_PATH: &'static str =
    "../test-program/target/wasm32-wasi/release/test-program.wasm";
/// The filename of the WASM binary when stored in Veracruz's Virtual File
/// System (VFS).
const WASM_BINARY_VFS_PATH: &'static str = "/test-program.wasm";
/// Path of the certificate for the program provider.
const PROGRAM_PROVIDER_CERTIFICATE_PATH: &'static str =
    "../test-collateral/program-provider-certificate";
/// Path of the certificate for the graph provider.
const GRAPH_PROVIDER_CERTIFICATE_PATH: &'static str =
    "../test-collateral/graph-provider-certificate";
/// Path of the certificate for the challenge provider.
const CHALLENGE_PROVIDER_CERTIFICATE_PATH: &'static str =
    "../test-collateral/graph-provider-certificate";
/// Path of the public key for the program provider.
const PROGRAM_PROVIDER_PUBLIC_KEY_PATH: &'static str =
    "../test-collateral/program-provider-key.pem";
/// Path of the public key for the graph provider.
const GRAPH_PROVIDER_PUBLIC_KEY_PATH: &'static str = "../test-collateral/graph-provider-key.pem";
/// Path of the public key for the challenge provider.
const CHALLENGE_PROVIDER_PUBLIC_KEY_PATH: &'static str =
    "../test-collateral/challenge-provider-key.pem";
/// The path of the policy file describing the roles of various principals in
/// the computation.
const POLICY_PATH: &'static str = "../test-collateral/policy.json";
/// The log settings for all of the various subcomponents that are about to be
/// exercised.
const RUST_LOG_SETTINGS: &'static str =
    "debug,actix_server=info,actix_web=info,tokio_reactor=info,hyper=info,reqwest=info,rustls=info";

////////////////////////////////////////////////////////////////////////////////
// Input and output conventions.
////////////////////////////////////////////////////////////////////////////////

/// The input graph is provided to us as a serialized (in Pinecone format)
/// struct capturing the structure of a directed weighted graph.
#[derive(Serialize)]
struct Graph {
    /// The nodes of the graph.
    nodes: HashSet<String>,
    /// A map from nodes to a list of the node's successor nodes, along with
    /// their weight.
    successors: HashMap<String, Vec<(String, i32)>>,
}

impl Graph {
    /// Creates a new, empty graph with no nodes and no edges.
    #[inline]
    pub fn new() -> Self {
        Graph {
            nodes: HashSet::new(),
            successors: HashMap::new(),
        }
    }

    /// Adds a new edge to the graph, from `source` to `sink` with a given
    /// `weight`, updating the node set as appropriate.
    pub fn add_edge(&mut self, source: String, weight: i32, sink: String) -> &mut Self {
        self.nodes.insert(source.clone());
        self.nodes.insert(sink.clone());

        if let Some(mut existing_successors) = self.successors.get(&source) {
            existing_successors.push((sink, weight));
            self.successors.insert(source, existing_successors.clone());
            self
        } else {
            self.successors.insert(source, vec![(sink, weight)]);
            self
        }
    }
}

/// A "challenge" represents a graph routing problem, consisting of a node to
/// start routing from and a node to end routing at.  We are therefore then
/// tasked with finding a route between the two nodes in the input graph.
#[derive(Serialize)]
struct Challenge {
    /// Node to start routing from.
    source: String,
    /// Node to end routing at.
    sink: String,
}

impl Challenge {
    /// Creates a new challenge from a `source` and a `sink` node.
    #[inline]
    pub fn new(source: String, sink: String) -> Self {
        Self { source, sink }
    }
}

/// A "response" represents a route through the graph, made in reponse to a
/// `Challenge`.  A route consists of a vector of graph nodes, representing a
/// path through the graph, from node-to-node.  Note that the routing process
/// may fail for a variety of reasons (e.g. the nodes in the challenge may not
/// be present in the graph, or the two nodes may be unconnected), in which case
/// we use the `CannotRoute` constructor to signal failure.
#[derive(Deserialize)]
enum Response {
    /// The graph is not valid.
    GraphInvalid,
    /// There is no route between the `from` and `to` nodes of the `Challenge`.
    CannotRoute,
    /// A route was found between the two nodes.  The route, or path, is
    /// represented as a series of nodes through the graph and is returned along
    /// with the total route weight.
    Route((Vec<String>, i32)),
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            Response::CannotRoute => write!(f, "No route was found."),
            Response::GraphInvalid => write!(f, "The input graph was invalid."),
            Response::Route((route, cost)) => {
                writeln!(
                    f,
                    "Route of length {} found with weight {}.",
                    route.len(),
                    cost
                )?;

                writeln!("{}", route.iter().join(" ⟶ "))
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Waiting to proceed.
////////////////////////////////////////////////////////////////////////////////

/// Prints a prompt to `stdout` asking for the user to provide input, then
/// blocks waiting for input.
fn wait_for_user() {
    println!(">>> Press any key to continue...");

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap_or_else(|e| {
        error!("Failed to read from stdin.  Error produced: {}.", e);
        exit(1)
    });
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

fn main() -> anyhow::Result<()> {
    /* Setup logging to make debugging any errors easier. */

    env_logger::init();
    std::env::set_var("RUST_LOG", RUST_LOG_SETTINGS);

    info!("Logging initialized (with: {}).", RUST_LOG_SETTINGS);

    wait_for_user();

    /* Read the policy file. */

    let mut policy_file = File::open(&POLICY_PATH).map_err(|e| {
        error!(
            "Failed to open policy file ({}).  Error produced: {}.",
            POLICY_PATH, e
        );
        e
    })?;

    let mut policy_content = String::new();
    policy_file
        .read_to_string(&mut policy_content)
        .map_err(|e| {
            error!(
                "Failed to read the content of the policy file ({}).  Error produced: {}.",
                POLICY_PATH, e
            );
            e
        })?;

    let policy = Policy::from_json(&policy_content).map_err(|e| {
        error!(
            "Failed to parse JSON policy file ({}).  Error produced: {:?}.",
            POLICY_PATH, e
        );
    })?;

    info!("Policy file read ({}).", POLICY_PATH);

    wait_for_user();

    /* Compute a hash of the content of the policy file. */

    let policy_hash = digest(&SHA256, policy_content.as_bytes());
    let hex_policy_hash = hex::encode(&policy_hash.as_ref().to_vec());

    info!("Policy file has SHA-256 hash: {}.", hex_policy_hash);

    wait_for_user();

    /* Start the Veracruz proxy attestation server. */

    let _main_loop_handle = spawn(|| {
        let mut sys = System::new("Veracruz Proxy Attestation Server");
        let server = proxy_attestation_server::server::server(
            policy.proxy_attestation_server_url().clone(),
            false,
        )
        .unwrap();
        sys.block_on(server).map_err(|e| {
            error!(
                "Failed to initialize Veracruz Proxy Attestation Server.  Error produced: {}.",
                e
            )
        });
    });

    sleep(Duration::from_secs(2));

    info!(
        "Veracruz Proxy Attestation Server now initialized (at {}).",
        policy.proxy_attestation_server_url()
    );

    wait_for_user();

    /* Bring up the Veracruz server. */

    let _veracruz_server_handle = veracruz_server::server::server(policy)
        .map_err(|e| {
            error!(
                "Failed to start the Veracruz Server.  Error produced: {:?}.",
                e
            );
            e
        })?
        .await?;

    sleep(Duration::from_secs(2));

    /* Describe the two clients that will be connecting to the server in the
     * computation.
     */

    let mut program_provider_client = VeracruzClient::new(
        PROGRAM_PROVIDER_CERTIFICATE_PATH,
        PROGRAM_PROVIDER_PUBLIC_KEY_PATH,
        &policy_content,
        &Platform::SGX,
    )
    .map_err(|e| {
        error!(
            "Failed to describe program provider principal.  Error produced: {:?}.",
            e
        );
    })?;

    let mut data_provider_client = VeracruzClient::new(
        DATA_PROVIDER_CERTIFICATE_PATH,
        DATA_PROVIDER_PUBLIC_KEY_PATH,
        &policy_content,
        &Platform::SGX,
    )
    .map_err(|e| {
        error!(
            "Failed to describe data provider principal.  Error produced: {:?}.",
            e
        );
    })?;

    info!("Data provider and program provider clients created.");

    wait_for_user();

    /* Read the WASM program in preparation of provisioning. */

    let mut wasm_binary_file = File::open(&WASM_BINARY_PATH).map_err(|e| {
        error!(
            "Failed to open WASM binary file ({}).  Error produced: {}.",
            WASM_BINARY_PATH, e
        );
        e
    })?;

    let mut wasm_binary_content = Vec::new();
    wasm_binary_file
        .read_to_end(&mut wasm_binary_content)
        .map_err(|e| {
            error!(
                "Failed to read content of WASM binary file ({}).  Error produced: {}.",
                WASM_BINARY_PATH, e
            );
            e
        })?;

    info!("WASM binary ({}) read successfully.", WASM_BINARY_PATH);

    wait_for_user();

    /* Compute the hash of the WASM binary. */

    let wasm_binary_hash = digest(&SHA256, &wasm_binary_content);
    let hex_wasm_binary_hash = hex::encode(&wasm_binary_hash.as_ref().to_vec());

    info!("WASM binary has SHA-256 hash: {}.", hex_wasm_binary_hash);

    wait_for_user();

    /* Provision the program, via the program provider client.  Note that this
     * implicitly checks that the policy in force is the one that is expected.
     */

    program_provider_client
        .send_program(&WASM_BINARY_VFS_PATH, &wasm_binary_content)
        .map_err(|e| {
            error!(
                "Failed to provision WASM program ({}).  Error produced: {:?}.",
                WASM_BINARY_PATH, e
            );
        })?;

    program_provider_client.request_shutdown().map_err(|e| {
        error!(
            "Failed to shutdown program provider client.  Error produced: {:?}.",
            e
        );
    })?;

    info!(
        "WASM program ({}) provisioned successfully.  Now stored in Veracruz VFS (at {}).",
        WASM_BINARY_PATH, WASM_BINARY_VFS_PATH
    );

    wait_for_user();

    /* Read the data input in preparation of provisioning. */

    let mut data_input_file = File::open(&INPUT_DATASET_PATH).map_err(|e| {
        error!(
            "Failed to open data input file ({}).  Error produced: {}.",
            INPUT_DATASET_PATH, e
        );
        e
    })?;

    let mut data_input_content = Vec::new();
    data_input_file
        .read_to_end(&mut data_input_content)
        .map_err(|e| {
            error!(
                "Failed to read content of data input file ({}).  Error produced: {}.",
                INPUT_DATASET_PATH, e
            );
            e
        })?;

    info!("Data input ({}) read successfully.", INPUT_DATASET_PATH);

    wait_for_user();

    /* Provision the data input, via the data provider client. Note that this
     * also implicitly checks that the policy in force is the one that is
     * expected.
     */

    data_provider_client
        .send_data(INPUT_DATASET_VFS_PATH, &data_input_content)
        .map_err(|e| {
            error!(
                "Failed to provision data input ({}).  Error produced: {:?}.",
                INPUT_DATASET_PATH, e
            );
        })?;

    info!(
        "Data input ({}) provisioned successfully.  Now stored in Veracruz VFS (at {}).",
        INPUT_DATASET_PATH, INPUT_DATASET_VFS_PATH
    );

    wait_for_user();

    /* Now, everything is in place to request the result. */

    let result = data_provider_client
        .get_results(&WASM_BINARY_VFS_PATH)
        .map_err(|e| {
            error!(
                "Failed to retrieve result of computation.  Error produced: {:?}.",
                e
            );
        })?;

    info!("Received {} bytes of result.", result.len());

    wait_for_user();

    /* Now, decode the raw result into something more intelligible. */

    let result: f32 = from_bytes(&result).map_err(|e| {
        error!("Failed to decode result.  Error produced: {}.", e);
    })?;

    info!("Decoded result: {}.", result);

    wait_for_user();

    /* Shutdown the data provider client gracefully. */

    data_provider_client.request_shutdown().map_err(|e| {
        error!(
            "Failed to shutdown data input provider client.  Error produced: {:?}.",
            e
        );
    })?;

    info!("All done...");

    Ok(())
}
