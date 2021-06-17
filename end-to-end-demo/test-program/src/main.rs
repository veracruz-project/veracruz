//! Program for the Veracruz end-to-end demo
//!
//! Implements a simple form of oblivious routing in a map, represented as a
//! graph of "ways" (i.e. roads, motorways, etc.) between nodes with a given
//! weight that captures the capacity of the "way".  Uses the A-Star routing
//! algorithm to find the shortest route (calculated using the weights) between
//! two nodes in the graph, should one exist.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE.markdown` file in the Veracruz repository root directory
//! for licensing and copyright information.

use anyhow::{Context, Result};
use petgraph::graph::NodeIndex;
use petgraph::{algo::astar, Directed, Graph};
use pinecone::{from_bytes, to_vec};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Path in the Veracruz Virtual File System (VFS) where the serialized input
/// graph is stored.
const GRAPH_INPUT_PATH: &'static str = "input-graph.dat";
/// Path in the Veracruz Virtual File System (VFS) where the serialized routing
/// challenge is stored.
const CHALLENGE_INPUT_PATH: &'static str = "challenge-input.dat";
/// Path in the Veracruz Virtual File System (VFS) where the serialized output
/// route will be stored.
const RESPONSE_OUTPUT_PATH: &'static str = "response-output.dat";

////////////////////////////////////////////////////////////////////////////////
// Input and output conventions.
////////////////////////////////////////////////////////////////////////////////

/// The input graph is provided to us as a serialized (in Pinecone format)
/// struct containing a vector of node-node pairs, with an additional "weight",
/// where nodes are represented as Rust `String`s.  A given triple `(e, f, w)`
/// in the vector asserts the existence of a directed edge from node `e` to node
/// `f` with weight `w`.
#[derive(Deserialize)]
struct SerializedGraph {
    /// The edges of the graph, encoding connections between nodes represented
    /// as a `String`, with a given weight, capturing e.g. timing information,
    /// length, traffic-carrying capacity, and so on.
    edges: Vec<(String, String, i32)>,
}

/// A "challenge" represents a graph routing problem, consisting of a node to
/// start routing from and a node to end routing at.  We are therefore then
/// tasked with finding a route between the two nodes in the input graph.
#[derive(Deserialize)]
struct Challenge {
    /// Node to start routing from.
    from: String,
    /// Node to end routing at.
    to: String,
}

/// A "response" represents a route through the graph, made in reponse to a
/// `Challenge`.  A route consists of a vector of graph nodes, representing a
/// path through the graph, from node-to-node.  Note that the routing process
/// may fail for a variety of reasons (e.g. the nodes in the challenge may not
/// be present in the graph, or the two nodes may be unconnected), in which case
/// we use the `CannotRoute` constructor to signal failure.
#[derive(Serialize)]
enum Response {
    /// There is no route between the `from` and `to` nodes of the `Challenge`.
    CannotRoute,
    /// A route was found between the two nodes.  The route, or path, is
    /// represented as a series of nodes through the graph and is returned along
    /// with the total route weight.
    Route((Vec<String>, i32)),
}

////////////////////////////////////////////////////////////////////////////////
// Routing.
////////////////////////////////////////////////////////////////////////////////

fn construct_graph(
    edges: &[(String, String, i32)],
    from: &String,
    to: &String,
) -> (Graph<String, i32, Directed, u32>, NodeIndex, NodeIndex) {
    unimplemented!()
}

/// Calculates a route through `graph` using the `from` and `to` points using
/// the A-Star pathfinding algorithm.  Returns `Response::Route(route, weight)`
/// if a `route` is found with a calculated `weight`.  Otherwise, returns
/// `Response::CannotRoute`.
fn calculate_route(
    graph: &Graph<String, i32, Directed, u32>,
    from: NodeIndex,
    to: NodeIndex,
) -> Response {
    if let Some((weight, route)) = astar(graph, from, |finish| finish == to, |e| e.weight(), |_| &0)
    {
        Response::Route((route, *weight))
    } else {
        Response::CannotRoute
    }
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

/// Entry point for the calculation: reads the secret graph and routing
/// challenge from the Virtual File System (VFS), deserializes them, performs
/// routing, and then writes the serialized result back to the VFS.
fn main() -> Result<()> {
    /* Read the graph input. */

    let mut serialized_graph_file =
        File::open(&GRAPH_INPUT_PATH).context("Failed to read graph input file.")?;

    let mut buffer = Vec::new();
    serialized_graph_file
        .read_to_end(&mut buffer)
        .context("Failed to read graph input file to end.")?;

    let graph: SerializedGraph =
        from_bytes(&buffer).context("Failed to deserialize graph input file.")?;

    /* Read the secret challenge. */

    let mut serialized_challenge_file =
        File::open(&CHALLENGE_INPUT_PATH).context("Failed to read challenge input file.")?;

    let mut buffer = Vec::new();
    serialized_challenge_file
        .read_to_end(&mut buffer)
        .context("Failed to read input challenge file to end.")?;

    let challenge: Challenge =
        from_bytes(&buffer).context("Failed to deserialize challenge input file.")?;

    /* Perform routing. */

    let (graph, from, to) = construct_graph(&graph.edges, &challenge.from, &challenge.to);
    let route = calculate_route(&graph, from, to);

    /* Serialize and write the result back. */

    let mut serialized_output_file =
        File::open(RESPONSE_OUTPUT_PATH).context("Failed to open output file for writing.")?;

    let serialized_output = to_vec(&route).context("Failed to serialize the routing result.")?;

    serialized_output_file
        .write_all(&serialized_output)
        .context("Failed to write result to output file.")?;

    Ok(())
}
