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
use pathfinding::directed::astar::astar;
use pinecone::{from_bytes, to_vec};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::{
    fs::File,
    io::{Read, Write},
};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Path in the Veracruz Virtual File System (VFS) where the serialized input
/// graph is stored.
const GRAPH_INPUT_PATH: &'static str = "/routing-graph.dat";
/// Path in the Veracruz Virtual File System (VFS) where the serialized routing
/// challenge is stored.
const CHALLENGE_INPUT_PATH: &'static str = "/routing-challenge.dat";
/// Path in the Veracruz Virtual File System (VFS) where the serialized output
/// route will be stored.
const RESPONSE_OUTPUT_PATH: &'static str = "/routing-response.dat";

////////////////////////////////////////////////////////////////////////////////
// Input and output conventions.
////////////////////////////////////////////////////////////////////////////////

/// The input graph is provided to us as a serialized (in Pinecone format)
/// struct capturing the structure of a directed weighted graph.
#[derive(Deserialize)]
struct Graph {
    /// The nodes of the graph.
    nodes: HashSet<String>,
    /// A map from nodes to a list of the node's successor nodes, along with
    /// their weight.
    successors: HashMap<String, Vec<(String, i32)>>,
}

impl Graph {
    /// Returns the set of successor nodes of a particular node, if any.
    pub fn successors(&self, node: &String) -> Vec<(String, i32)> {
        if let Some(succs) = self.successors.get(node) {
            succs.clone()
        } else {
            Vec::new()
        }
    }

    /// Returns `true` iff the `node` is a node of the graph.
    #[inline]
    pub fn is_graph_node(&self, node: &String) -> bool {
        self.nodes.contains(node)
    }

    /// Returns `true` iff the representation of the graph is valid, in the
    /// sense that:
    /// 1. Every node has a list of successor nodes (even if empty),
    /// 2. Every node mentioned in the successor map is contained in the set of
    ///    nodes.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.nodes.iter().all(|n| self.successors.contains_key(n))
            && self.successors.iter().all(|(n, succs)| {
                self.is_graph_node(n) && succs.iter().all(|(n, _w)| self.is_graph_node(n))
            })
    }
}

/// A "challenge" represents a graph routing problem, consisting of a node to
/// start routing from and a node to end routing at.  We are therefore then
/// tasked with finding a route between the two nodes in the input graph.
#[derive(Deserialize)]
struct Challenge {
    /// Node to start routing from.
    source: String,
    /// Node to end routing at.
    sink: String,
}

impl Challenge {
    /// Returns the source, or start node of the challenge.
    #[inline]
    pub fn source(&self) -> &String {
        &self.source
    }

    /// Returns the sink, or end node of the challenge.
    #[inline]
    pub fn sink(&self) -> &String {
        &self.sink
    }
}

/// A "response" represents a route through the graph, made in reponse to a
/// `Challenge`.  A route consists of a vector of graph nodes, representing a
/// path through the graph, from node-to-node.  Note that the routing process
/// may fail for a variety of reasons (e.g. the nodes in the challenge may not
/// be present in the graph, or the two nodes may be unconnected), in which case
/// we use the `CannotRoute` constructor to signal failure.
#[derive(Serialize)]
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

////////////////////////////////////////////////////////////////////////////////
// Routing.
////////////////////////////////////////////////////////////////////////////////

/// Calculates a route through `graph` using the `from` and `to` points using
/// the A-Star pathfinding algorithm.  Returns `Response::Route(route, weight)`
/// if a `route` is found with a calculated `weight`.  Otherwise, returns
/// `Response::CannotRoute`.
fn calculate_route(serialized_graph: &Graph, from: &String, to: &String) -> Response {
    if !serialized_graph.is_valid() {
        Response::GraphInvalid
    } else {
        if let Some((route, weight)) = astar(
            from,
            |node| serialized_graph.successors(node),
            |_e| 0,
            |e| e == to,
        ) {
            Response::Route((route, weight))
        } else {
            Response::CannotRoute
        }
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
    
    let graph: Graph = from_bytes(&buffer).context("Failed to deserialize graph input file.")?;

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

    let route = calculate_route(&graph, &challenge.source(), &challenge.sink());

    /* Serialize and write the result back. */

    let mut serialized_output_file =
        File::create(RESPONSE_OUTPUT_PATH).context("Failed to open output file for writing.")?;
    
    let serialized_output = to_vec(&route).context("Failed to serialize the routing result.")?;

    serialized_output_file
        .write_all(&serialized_output)
        .context("Failed to write result to output file.")?;
    
    Ok(())
}
