//! End-to-end demo.
//!
//! A demo showing how to develop and deploy applications on-top of the Veracruz
//! framework.  Demonstrates provisioning secrets into the enclave via a secure
//! TLS link.
//!
//! We use an oblivious routing example, here, wherein a user wishes to query a
//! map (expressed as a graph of locations connected by roads, along with their
//! approximate distance in miles) without the mapping service knowing where
//! they are starting from, or where they are going.  As a result, there are
//! two principals involved in the computation:
//!
//! 1. The mapping service, which produces the connectivity map and all of its
//!    metadata, which is going to be queried, and also supplies the program
//!    that will actually perform the routing (see the contents of
//!    `test-program`).
//! 2. The user, who issues a "routing challenge" to the mapping service asking
//!    it to compute a route from location `A` to location `B`.  Note that in
//!    this computation, it is the user that will be able to retrieve the result
//!    with all routing shielded from the routing service itself by the enclave.
//!
//! In a real deployment, these two principals will obviously distinct,
//! possessing their own machines through which they interact with the Veracruz
//! runtime, though here for the purposes of demonstrating Veracruz we use a
//! single thread of execution with two different clients to represent the two
//! principals.
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
use rand::seq::SliceRandom;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{Display, Error as FormatError, Formatter},
    fs::File,
    io::Read,
    path::Path,
    thread::{sleep, spawn},
    time::Duration,
};

use pinecone::{from_bytes, to_vec};
use proxy_attestation_server;
use std::io::stdin;
use std::process::exit;
use veracruz_client::VeracruzClient;
use veracruz_server;
use veracruz_utils::{platform::Platform, policy::policy::Policy};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// The path of the WASM routing program supplied by the mapping service that
/// will be used for the collaborative computation.
const WASM_BINARY_PATH: &'static str =
    "../test-program/target/wasm32-wasi/release/test-program.wasm";
/// The filename of the WASM binary when stored in Veracruz's Virtual File
/// System (VFS).
const WASM_BINARY_VFS_PATH: &'static str = "/test-program.wasm";
/// The filename of the routing graph when stored in Veracruz's Virtual File
/// System (VFS).
const ROUTING_GRAPH_VFS_PATH: &'static str = "/routing-graph";
/// The filename of the routing challenge when stored in Veracruz's Virtual File
/// System (VFS).
const ROUTING_CHALLENGE_VFS_PATH: &'static str = "/routing-challenge";
/// Path of the certificate for the program provider.
const MAPPING_SERVICE_CERTIFICATE_PATH: &'static str =
    "../test-collateral/mapping-service-certificate";
/// Path of the certificate for the mapping user/challenge provider.
const MAPPING_USER_PROVIDER_CERTIFICATE_PATH: &'static str =
    "../test-collateral/mapping-user-certificate";
/// Path of the public key for the mapping service.
const MAPPING_SERVICE_PUBLIC_KEY_PATH: &'static str =
    "../test-collateral/mapping-service-public-key.pem";
/// Path of the public key for the mapping user/challenge provider.
const MAPPING_USER_PUBLIC_KEY_PATH: &'static str = "../test-collateral/mapping-user-public-key.pem";
/// The path of the policy file describing the roles of various principals in
/// the computation.
const POLICY_PATH: &'static str = "../test-collateral/oblivious-routing-policy.json";
/// The log settings for all of the various subcomponents that are about to be
/// exercised.
const RUST_LOG_SETTINGS: &'static str =
    "debug,actix_server=info,actix_web=info,tokio_reactor=info,hyper=info,reqwest=info,rustls=info";

////////////////////////////////////////////////////////////////////////////////
// Input and output conventions.
////////////////////////////////////////////////////////////////////////////////

/// The input graph is provided to us as a serialized (in Pinecone format)
/// struct capturing the structure of a directed weighted graph.  Note that in a
/// real routing scenario this graph will need to be much more complex: we don't
/// even include road names here, for example, we just note whether two locations
/// are connected or not.  In the real world, locations may be connected by
/// multiple different routes, naturally.  A more realistic example of oblivious
/// routing could use OpenStreetMap data, for example.
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

    /// Adds a new directed edge to the graph, from `source` to `sink` with a
    /// given `weight`, updating the node set as appropriate.
    pub fn add_directed_edge<T, U>(&mut self, source: T, weight: U, sink: T) -> &mut Self
    where
        T: Into<String> + Clone,
        U: Into<i32>,
    {
        self.nodes.insert(source.clone().into());
        self.nodes.insert(sink.clone().into());

        if let Some(mut existing_successors) = self.successors.get(&source) {
            existing_successors.push((sink.into(), weight.into()));
            self.successors
                .insert(source.into(), existing_successors.clone());
            self
        } else {
            self.successors
                .insert(source.into(), vec![(sink.into(), weight.into())]);
            self
        }
    }

    /// Adds a new undirected edge to the graph (or rather, two directed edges
    /// pointing in both directions), from `first_node` to `second_node` with a
    /// given `weight`, updating the node set as appropriate.
    pub fn add_undirected_edge<T, U>(
        &mut self,
        first_node: T,
        weight: U,
        second_node: T,
    ) -> &mut Self
    where
        T: Into<String> + Clone,
        U: Into<i32> + Clone,
    {
        self.add_directed_edge(first_node.clone(), weight.clone(), second_node.clone())
            .add_directed_edge(second_node, weight, first_node)
    }
}

/// A "challenge" represents a graph routing problem, consisting of a node to
/// start routing from and a node to end routing at.  The routing service is
/// then tasked with finding a route between the two nodes in the input graph.
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
    pub fn new<T>(source: T, sink: T) -> Self
    where
        T: Into<String>,
    {
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

/// Pretty-printing for `Response` types.
impl Display for Response {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
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
// Input data.
////////////////////////////////////////////////////////////////////////////////

/// Generates a graph of locations around South Cambridgeshire and their
/// approximate distances (in miles) from each other.  This graph will be used
/// as one of the inputs to the collaborative computation.
fn generate_graph() -> Graph {
    let mut graph = Graph::new();

    graph
        .add_undirected_edge("Cottenham", 1, "Rampton")
        .add_undirected_edge("Cottenham", 3, "Wilburton")
        .add_undirected_edge("Cottenham", 2, "Landbeach")
        .add_undirected_edge("Cottenham", 2, "Histon")
        .add_undirected_edge("Cottenham", 3, "Oakington")
        .add_undirected_edge("Rampton", 1, "Willingham")
        .add_undirected_edge("Histon", 0, "Impington")
        .add_undirected_edge("Histon", 1, "Oakington")
        .add_undirected_edge("Histon", 1, "Girton")
        .add_undirected_edge("Impington", 1, "Milton")
        .add_undirected_edge("Milton", 1, "Landbeach")
        .add_undirected_edge("Milton", 1, "Clayhithe")
        .add_undirected_edge("Clayhithe", 1, "Horningsea")
        .add_undirected_edge("Horningsea", 1, "Fen Ditton")
        .add_undirected_edge("Willingham", 1, "Over")
        .add_undirected_edge("Willingham", 2, "Longstanton")
        .add_undirected_edge("Willingham", 1, "Earith")
        .add_undirected_edge("Earith", 3, "Haddenham");

    graph
}

/// Creates a new routing challenge by randomly choosing a source and a target
/// destination from the list of locations present in the graph.  This challenge
/// will be used as one of the inputs to the collaborative computation.
#[inline]
fn generate_challenge() -> Challenge {
    let locations = vec![
        "Clayhithe",
        "Cottenham",
        "Earith",
        "Haddenham",
        "Fen Ditton",
        "Girton",
        "Histon",
        "Impington",
        "Landbeach",
        "Longstanton",
        "Milton",
        "Oakington",
        "Over",
        "Rampton",
        "Wilburton",
        "Willingham",
    ];

    let first_location = locations
        .choose(&mut rand::thread_rng())
        .expect("Random location could not be chosen (locations list may be empty).");
    let second_location = locations
        .choose(&mut rand::thread_rng())
        .expect("Random location could not be chosen (locations list may be empty).");

    info!(
        "Chosen locations {} to {}.",
        first_location, second_location
    );

    Challenge::new(first_location, second_location)
}

////////////////////////////////////////////////////////////////////////////////
// Waiting to proceed.
////////////////////////////////////////////////////////////////////////////////

/// Prints a prompt to `stdout` asking for the user to provide input, then
/// blocks waiting for input.  This is just a simple utility function to help
/// "show off" the different stages of the Veracruz provisioning flow.
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

    info!(
        "Logging initialized (with settings: {}).",
        RUST_LOG_SETTINGS
    );

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

    let mut mapping_service_client = VeracruzClient::new(
        MAPPING_SERVICE_CERTIFICATE_PATH,
        MAPPING_SERVICE_PUBLIC_KEY_PATH,
        &policy_content,
        &Platform::SGX,
    )
    .map_err(|e| {
        error!(
            "Failed to describe mapping service client.  Error produced: {:?}.",
            e
        );
    })?;

    let mut mapping_user_client = VeracruzClient::new(
        DATA_PROVIDER_CERTIFICATE_PATH,
        DATA_PROVIDER_PUBLIC_KEY_PATH,
        &policy_content,
        &Platform::SGX,
    )
    .map_err(|e| {
        error!(
            "Failed to describe mapping user client.  Error produced: {:?}.",
            e
        );
    })?;

    info!("Mapping service and user clients created.");

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

    /* Generate and serialize the routing map. */

    let graph = generate_graph();
    let serialized_graph = to_vec(&graph).map_err(|e| {
        error!("Failed to serialize routing map.  Error produced: {}.", e);
    })?;

    /* Provision the program, via the program provider client.  Note that this
     * implicitly checks that the policy in force is the one that is expected.
     */

    mapping_service_client
        .send_program(&WASM_BINARY_VFS_PATH, &wasm_binary_content)
        .map_err(|e| {
            error!(
                "Failed to provision WASM program ({}).  Error produced: {:?}.",
                WASM_BINARY_PATH, e
            );
        })?;

    mapping_service_client
        .send_data(&ROUTING_GRAPH_VFS_PATH, &serialized_graph)
        .map_err(|e| {
            error!("Failed to provision routing map.  Error produced: {:?}.", e);
        })?;

    mapping_service_client.request_shutdown().map_err(|e| {
        error!(
            "Failed to shutdown program provider client.  Error produced: {:?}.",
            e
        );
    })?;

    info!(
        "WASM program ({}) and routing map provisioned successfully.  Now stored in Veracruz VFS (at {} and {}).",
        WASM_BINARY_PATH, WASM_BINARY_VFS_PATH, ROUTING_GRAPH_VFS_PATH
    );

    wait_for_user();

    /* Generate and serialize a routing challenge. */

    let challenge = generate_challenge();
    let serialized_challenge = to_vec(&challenge).map_err(|e| {
        error!(
            "Failed to serialize routing challenge.  Error produced: {:?}.",
            e
        );
    })?;

    info!(
        "Requesting route from {} to {}.",
        &challenge.source, &challenge.sink
    );

    wait_for_user();

    /* Provision the data input, via the data provider client. Note that this
     * also implicitly checks that the policy in force is the one that is
     * expected.
     */

    mapping_user_client
        .send_data(ROUTING_CHALLENGE_VFS_PATH, &serialized_challenge)
        .map_err(|e| {
            error!(
                "Failed to provision routing challenge input.  Error produced: {:?}.",
                e
            );
        })?;

    info!(
        "Routing challenge provisioned successfully.  Now stored in Veracruz VFS (at {}).",
        ROUTING_CHALLENGE_VFS_PATH
    );

    wait_for_user();

    /* Now, everything is in place to request the routing result. */

    let result = mapping_user_client
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

    let result: Response = from_bytes(&result).map_err(|e| {
        error!("Failed to decode routing response.  Error produced: {}.", e);
    })?;

    info!("Decoded result: {}.", result);

    wait_for_user();

    /* Shutdown the data provider client gracefully. */

    mapping_user_client.request_shutdown().map_err(|e| {
        error!(
            "Failed to shutdown data input provider client.  Error produced: {:?}.",
            e
        );
    })?;

    info!("All done...");

    Ok(())
}
