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
use env_logger;
use rand::seq::SliceRandom;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Error as FormatError, Formatter},
    fs::File,
    io::Read,
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
    "oblivious-routing/target/wasm32-wasi/release/oblivious-routing.wasm";
/// The filename of the WASM binary when stored in Veracruz's Virtual File
/// System (VFS).
const WASM_BINARY_VFS_PATH: &'static str = "oblivious-routing.wasm";
/// The filename of the routing graph when stored in Veracruz's Virtual File
/// System (VFS).
const ROUTING_GRAPH_VFS_PATH: &'static str = "routing-graph.dat";
/// The filename of the routing challenge when stored in Veracruz's Virtual File
/// System (VFS).
const ROUTING_CHALLENGE_VFS_PATH: &'static str = "routing-challenge.dat";
/// Path of the certificate for the program provider.
const MAPPING_SERVICE_CERTIFICATE_PATH: &'static str =
    "test-collateral/mapping-service-certificate.pem";
/// Path of the certificate for the mapping user/challenge provider.
const MAPPING_USER_CERTIFICATE_PATH: &'static str = "test-collateral/mapping-user-certificate.pem";
/// Path of the public key for the mapping service.
const MAPPING_SERVICE_PUBLIC_KEY_PATH: &'static str = "test-collateral/mapping-service-key.pem";
/// Path of the public key for the mapping user/challenge provider.
const MAPPING_USER_PUBLIC_KEY_PATH: &'static str = "test-collateral/mapping-user-key.pem";
/// The path of the policy file describing the roles of various principals in
/// the computation.
const POLICY_PATH: &'static str = "test-collateral/oblivious-routing-policy.json";
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

        if let Some(existing_successors) = self.successors.get(&source.clone().into()) {
            let mut existing_successors = existing_successors.clone();
            existing_successors.push((sink.into(), weight.into()));
            self.successors.insert(source.into(), existing_successors);
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
        Self {
            source: source.into(),
            sink: sink.into(),
        }
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

                writeln!(f, "{}", route.join(" ⟶ "))
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
        .add_undirected_edge("Cottenham", 2700, "Rampton")
        .add_undirected_edge("Cottenham", 8800, "Wilburton")
        .add_undirected_edge("Cottenham", 4000, "Landbeach")
        .add_undirected_edge("Cottenham", 5400, "Histon")
        .add_undirected_edge("Cottenham", 5800, "Oakington")
        .add_undirected_edge("Aldreth", 2600, "Haddenham")
        .add_undirected_edge("Rampton", 4000, "Willingham")
        .add_undirected_edge("Histon", 1500, "Impington")
        .add_undirected_edge("Histon", 3600, "Oakington")
        .add_undirected_edge("Histon", 3300, "Girton")
        .add_undirected_edge("Impington", 4200, "Milton")
        .add_undirected_edge("Oakington", 2700, "Girton")
        .add_undirected_edge("Milton", 2800, "Landbeach")
        .add_undirected_edge("Milton", 3600, "Waterbeach")
        .add_undirected_edge("Waterbeach", 1300, "Clayhithe")
        .add_undirected_edge("Waterbeach", 2500, "Landbeach")
        .add_undirected_edge("Waterbeach", 6600, "Chittering")
        .add_undirected_edge("Chittering", 5700, "Stretham")
        .add_undirected_edge("Stretham", 3300, "Wilburton")
        .add_undirected_edge("Stretham", 7700, "Upware")
        .add_undirected_edge("Stretham", 7600, "Wicken")
        .add_undirected_edge("Clayhithe", 2200, "Horningsea")
        .add_undirected_edge("Horningsea", 2400, "Fen Ditton")
        .add_undirected_edge("Willingham", 3400, "Over")
        .add_undirected_edge("Willingham", 4600, "Longstanton")
        .add_undirected_edge("Willingham", 5900, "Earith")
        .add_undirected_edge("Earith", 8500, "Haddenham")
        .add_undirected_edge("Earith", 1900, "Bluntisham")
        .add_undirected_edge("Earith", 2100, "Colne")
        .add_undirected_edge("Colne", 1000, "Bluntisham")
        .add_undirected_edge("Wilburton", 2200, "Haddenham")
        .add_undirected_edge("Upware", 1500, "River Bank")
        .add_undirected_edge("Upware", 4900, "Wicken")
        .add_undirected_edge("River Bank", 5600, "Reach")
        .add_undirected_edge("River Bank", 6900, "Swaffham Prior")
        .add_undirected_edge("Reach", 2400, "Swaffham Prior")
        .add_undirected_edge("Commercial End", 1800, "Swaffham Prior")
        .add_undirected_edge("Commercial End", 1300, "Swaffham Bulbeck")
        .add_undirected_edge("Swaffham Bulbeck", 2400, "Swaffham Prior")
        .add_undirected_edge("Swaffham Bulbeck", 2500, "Bottisham")
        .add_undirected_edge("Swaffham Bulbeck", 4600, "Stow cum Quy")
        .add_undirected_edge("Bottisham", 2700, "Stow cum Quy")
        .add_undirected_edge("Stow cum Quy", 4600, "Fen Ditton")
        .add_undirected_edge("Longstanton", 3900, "Bar Hill")
        .add_undirected_edge("Bar Hill", 5000, "Oakington")
        .add_undirected_edge("Orchard Park", 3800, "Histon")
        .add_undirected_edge("Orchard Park", 3100, "Impington")
        .add_undirected_edge("Stretham", 3300, "Little Thetford")
        .add_undirected_edge("Stretham", 6900, "Ely")
        .add_undirected_edge("Little Thetford", 5000, "Ely")
        .add_undirected_edge("Ely", 4200, "Witchford")
        .add_undirected_edge("Witchford", 5900, "Little Thetford")
        .add_undirected_edge("Witchford", 4800, "Stretham")
        .add_undirected_edge("Witchford", 6500, "Wilburton")
        .add_undirected_edge("Witchford", 6300, "Haddenham");

    graph
}

/// Creates a new routing challenge by randomly choosing a source and a target
/// destination from the list of locations present in the graph.  This challenge
/// will be used as one of the inputs to the collaborative computation.
#[inline]
fn generate_challenge() -> Challenge {
    let locations = vec![
        "Aldreth",
        "Bar Hill",
        "Bluntisham",
        "Bottisham",
        "Chittering",
        "Clayhithe",
        "Colne",
        "Commercial End",
        "Cottenham",
        "Earith",
        "Ely",
        "Haddenham",
        "Fen Ditton",
        "Girton",
        "Histon",
        "Impington",
        "Landbeach",
        "Little Thetford",
        "Longstanton",
        "Milton",
        "Oakington",
        "Orchard Park",
        "Over",
        "Rampton",
        "Reach",
        "River Bank",
        "Stow cum Quy",
        "Stretham",
        "Swaffham Bulbeck",
        "Swaffham Prior",
        "Upware",
        "Wicken",
        "Wilburton",
        "Willingham",
        "Witchford",
    ];

    let first_location = locations
        .choose(&mut rand::thread_rng())
        .expect("Random location could not be chosen (locations list may be empty).")
        .clone();

    let second_location = locations
        .choose(&mut rand::thread_rng())
        .expect("Random location could not be chosen (locations list may be empty).")
        .clone();

    Challenge::new(first_location, second_location)
}

////////////////////////////////////////////////////////////////////////////////
// Waiting to proceed.
////////////////////////////////////////////////////////////////////////////////

/// Prints a prompt to `stdout` describing the next step and thereafter asking for
/// the user to provide input, then blocks waiting for input.  This is just a simple
/// utility function to help "show off" the different stages of the Veracruz
/// provisioning flow.
fn wait_for_user<T>(msg: T)
where
    T: AsRef<str>,
{
    println!("\nNext step: {}\n", msg.as_ref());
    println!(">>> Press any key to continue...");

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap_or_else(|e| {
        eprintln!("Failed to read from stdin.  Error produced: {}.", e);
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

    println!(
         "Logging initialized (with settings: {}).\nNote: run end-to-end-demo with `RUST_LOG=info,error` set to debug runtime failures in Veracruz code.",
         RUST_LOG_SETTINGS
    );

    wait_for_user(format!("Reading policy file ({}).", POLICY_PATH));

    /* Read the policy file. */

    let mut policy_file = File::open(&POLICY_PATH).map_err(|e| {
        eprintln!(
            "Failed to open policy file ({}).  Error produced: {}.",
            POLICY_PATH, e
        );
        e
    })?;

    let mut policy_content = String::new();
    policy_file
        .read_to_string(&mut policy_content)
        .map_err(|e| {
            eprintln!(
                "Failed to read the content of the policy file ({}).  Error produced: {}.",
                POLICY_PATH, e
            );
            e
        })?;

    let policy = Policy::from_json(&policy_content).map_err(|e| {
        eprintln!(
            "Failed to parse JSON policy file ({}).  Error produced: {:?}.",
            POLICY_PATH, e
        );
        e
    })?;

    let policy_hash = digest(&SHA256, policy_content.as_bytes());
    let hex_policy_hash = hex::encode(&policy_hash.as_ref().to_vec());

    println!(
        "Policy file read, and has SHA-256 hash: {}.",
        hex_policy_hash
    );

    wait_for_user("Bringing up the Veracruz Proxy Attestation Server, which abstracts over the various attestation protocols in use within Veracruz.");

    /* Start the Veracruz proxy attestation server. */

    let proxy_attestation_server_url = policy.proxy_attestation_server_url().clone();

    let _main_loop_handle = spawn(|| {
        let mut sys = System::new("Veracruz Proxy Attestation Server");

        let server =
            proxy_attestation_server::server::server(proxy_attestation_server_url, false).unwrap();

        let _result = sys.block_on(server).map_err(|e| {
            eprintln!(
                "Failed to initialize Veracruz Proxy Attestation Server.  Error produced: {}.",
                e
            );
            e
        });
    });

    println!("Veracruz Proxy Attestation Server initializing.  Waiting 10 seconds to complete...");

    sleep(Duration::from_secs(10));

    println!(
        "Veracruz Proxy Attestation Server now initialized and listening at {}.",
        policy.proxy_attestation_server_url()
    );

    wait_for_user("Bringing up the Veracruz Server, which acts as a bridge between untrusted and trusted code.");

    /* Bring up the Veracruz server. */

    let _veracruz_server_handle = spawn(move || {
        let mut sys = System::new("Veracruz Server");

        let server = veracruz_server::server::server(&POLICY_PATH).unwrap();

        let _result = sys.block_on(server).map_err(|e| {
            eprintln!(
                "Failed to initialize Veracruz Server.  Error produced: {}.",
                e
            );
            e
        });
    });

    println!("Veracruz Server initializing.  Waiting 10 seconds to complete...");

    sleep(Duration::from_secs(10));

    println!("Veracruz Server now initialized, and trusted Veracruz runtime code attested against expected hash in the policy.");

    wait_for_user("Creating two clients: one for the mapping service provider through which they provision the routing program and the underlying graph data, and the other for the mapping service user, through which they provision the routing challenge and retrieve the computed route.");

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
        eprintln!(
            "Failed to describe mapping service client.  Error produced: {:?}.",
            e
        );
        e
    })?;

    let mut mapping_user_client = VeracruzClient::new(
        MAPPING_USER_CERTIFICATE_PATH,
        MAPPING_USER_PUBLIC_KEY_PATH,
        &policy_content,
        &Platform::SGX,
    )
    .map_err(|e| {
        eprintln!(
            "Failed to describe mapping user client.  Error produced: {:?}.",
            e
        );
        e
    })?;

    println!("Mapping service and user clients created, and certificates checked against the policy file.");

    wait_for_user(
        "WASM binary opened and provisioned into trusted Veracruz runtime via secure TLS link.",
    );

    /* Read the WASM program in preparation of provisioning. */

    let mut wasm_binary_file = File::open(&WASM_BINARY_PATH).map_err(|e| {
        eprintln!(
            "Failed to open WASM binary file ({}).  Error produced: {}.",
            WASM_BINARY_PATH, e
        );
        e
    })?;

    let mut wasm_binary_content = Vec::new();
    wasm_binary_file
        .read_to_end(&mut wasm_binary_content)
        .map_err(|e| {
            eprintln!(
                "Failed to read content of WASM binary file ({}).  Error produced: {}.",
                WASM_BINARY_PATH, e
            );
            e
        })?;

    let wasm_binary_hash = digest(&SHA256, &wasm_binary_content);
    let hex_wasm_binary_hash = hex::encode(&wasm_binary_hash.as_ref().to_vec());

    println!(
        "WASM binary read successfull and has SHA-256 hash: {}.",
        hex_wasm_binary_hash
    );

    wait_for_user("Obtain the routing map.");

    /* Generate and serialize the routing map. */

    let graph = generate_graph();
    let serialized_graph = to_vec(&graph).map_err(|e| {
        eprintln!("Failed to serialize routing map.  Error produced: {}.", e);
        e
    })?;

    println!("Graph read (nodes: {}).", graph.nodes.len());

    wait_for_user("The Mapping Service Client provisions the routing binary and graph securely into the Veracruz runtime, via TLS.  These will be both stored in the Veracruz runtime's Virtual File System (VFS) at paths specified in the policy file.");

    /* Provision the program, via the program provider client.  Note that this
     * implicitly checks that the policy in force is the one that is expected.
     */

    mapping_service_client
        .send_program(&WASM_BINARY_VFS_PATH, &wasm_binary_content)
        .map_err(|e| {
            eprintln!(
                "Failed to provision WASM program ({}).  Error produced: {:?}.",
                WASM_BINARY_PATH, e
            );
            e
        })?;

    mapping_service_client
        .send_data(&ROUTING_GRAPH_VFS_PATH, &serialized_graph)
        .map_err(|e| {
            eprintln!("Failed to provision routing map.  Error produced: {:?}.", e);
            e
        })?;

    mapping_service_client.request_shutdown().map_err(|e| {
        eprintln!(
            "Failed to shutdown program provider client.  Error produced: {:?}.",
            e
        );
        e
    })?;

    println!(
        "WASM program ({}) and routing map provisioned successfully.  Now stored in Veracruz VFS at {} and {}.",
        WASM_BINARY_PATH, WASM_BINARY_VFS_PATH, ROUTING_GRAPH_VFS_PATH
    );

    wait_for_user("Generate a routing challenge.");

    /* Generate and serialize a routing challenge. */

    let challenge = generate_challenge();
    let serialized_challenge = to_vec(&challenge).map_err(|e| {
        eprintln!(
            "Failed to serialize routing challenge.  Error produced: {:?}.",
            e
        );
        e
    })?;

    println!(
        "Routing challenge successfully generated: requesting a route from {} to {}.",
        &challenge.source, &challenge.sink
    );

    wait_for_user("The Mapping User Client provisions the routing challenge securely into the Veracruz runtime via TLS.  This is again stored in a file in the Veracruz runtime's Virtual File System (VFS) as specified in the policy, ready for reading by the routing program.");

    /* Provision the data input, via the data provider client. Note that this
     * also implicitly checks that the policy in force is the one that is
     * expected.
     */

    mapping_user_client
        .send_data(ROUTING_CHALLENGE_VFS_PATH, &serialized_challenge)
        .map_err(|e| {
            eprintln!(
                "Failed to provision routing challenge input.  Error produced: {:?}.",
                e
            );
            e
        })?;

    println!(
        "Routing challenge provisioned successfully.  Now stored in Veracruz VFS at {}.",
        ROUTING_CHALLENGE_VFS_PATH
    );

    wait_for_user("Everything is now in place, and the Mapping User Client can request the result of the computation.");

    /* Now, everything is in place to request the routing result. */

    let result = mapping_user_client
        .get_results(&WASM_BINARY_VFS_PATH)
        .map_err(|e| {
            eprintln!(
                "Failed to retrieve result of computation.  Error produced: {:?}.",
                e
            );
            e
        })?;

    println!(
        "Computation successfully completed, received {} bytes of result.",
        result.len()
    );

    wait_for_user("We now decode the result into something more intelligible.");

    /* Now, decode the raw result into something more intelligible. */

    let result: Response = from_bytes(&result).map_err(|e| {
        eprintln!("Failed to decode routing response.  Error produced: {}.", e);
        e
    })?;

    println!("Computed route: {}", result);

    wait_for_user(
        "We request a shutdown of the various Veracruz components, via the Mapping User Client.",
    );

    /* Shutdown the data provider client gracefully. */

    mapping_user_client.request_shutdown().map_err(|e| {
        eprintln!(
            "Failed to shutdown data input provider client.  Error produced: {:?}.",
            e
        );
        e
    })?;

    println!("All done...");

    Ok(())
}
