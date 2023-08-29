//! Veracruz test material
//!
//! One of the main Veracruz integration tests, as lots of material is imported
//! directly or indirectly, here.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

mod common;

use common::event::TestEvent;
use common::proxy_attestation_server::*;
use common::util::*;

// Policies
const SINGLE_CLIENT_POLICY: &'static str = "single_client.json";
const LINEAR_REGRESSION_DUAL_POLICY: &'static str = "dual_policy.json";
const LINEAR_REGRESSION_TRIPLE_POLICY: &'static str = "triple_policy_1.json";
const LINEAR_REGRESSION_PARALLEL_POLICY: &'static str = "dual_parallel_policy.json";
const INTERSECTION_SET_SUM_TRIPLE_POLICY: &'static str = "triple_policy_2.json";
const STRING_EDIT_DISTANCE_TRIPLE_POLICY: &'static str = "triple_policy_4.json";
const STRING_EDIT_DISTANCE_QUADRUPLE_POLICY: &'static str = "quadruple_policy.json";

// Identities
const PROGRAM_CLIENT_CERT: &'static str = "program_client_cert.pem";
const PROGRAM_CLIENT_KEY: &'static str = "program_client_key.pem";
const RESULT_CLIENT_CERT: &'static str = "result_client_cert.pem";
const RESULT_CLIENT_KEY: &'static str = "result_client_key.pem";
const CLIENT_CERT: &'static str = "client_cert.pem";
const CLIENT_KEY: &'static str = "client_key.pem";
const DATA_CLIENT_CERT: &'static str = "data_client_cert.pem";
const DATA_CLIENT_KEY: &'static str = "data_client_key.pem";
const DATA_CLIENT_SECOND_CERT: &'static str = "never_used_cert.pem";
const DATA_CLIENT_SECOND_KEY: &'static str = "never_used_key.pem";

// Programs
const CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM: &'static str = "intersection-set-sum.wasm";
const STRING_EDIT_DISTANCE_WASM: &'static str = "string-edit-distance.wasm";
const LINEAR_REGRESSION_WASM: &'static str = "linear-regression.wasm";
const RANDOM_SOURCE_WASM: &'static str = "random-source.wasm";

// Data
const LINEAR_REGRESSION_DATA: &'static str = "linear-regression.dat";
const INTERSECTION_SET_SUM_CUSTOMER_DATA: &'static str = "intersection-customer.dat";
const INTERSECTION_SET_SUM_ADVERTISEMENT_DATA: &'static str =
    "intersection-advertisement-viewer.dat";
const STRING_1_DATA: &'static str = "hello-world-1.dat";
const STRING_2_DATA: &'static str = "hello-world-2.dat";

use anyhow::{anyhow, Result};
use env_logger;
use log::{error, info};
use policy_utils::policy::Policy;
use std::{env, path::Path, thread, time::Instant};
use veracruz_client::{self, VeracruzClient};
use veracruz_server::{self, VeracruzServer};

/// A test of veracruz using network communication using a single session
#[test]
fn veracruz_phase1_get_random_one_client() {
    TestExecutor::test_template(
        SINGLE_CLIENT_POLICY,
        &vec![(CLIENT_CERT, CLIENT_KEY)],
        vec![
            (0, TestEvent::write_program(RANDOM_SOURCE_WASM)),
            (0, TestEvent::execute(RANDOM_SOURCE_WASM)),
            (0, TestEvent::read_result("/output/random.dat")),
            (0, TestEvent::ShutDown),
        ],
    )
    .unwrap();
}

/// A test of veracruz using network communication using two sessions (one for program and one for data)
#[test]
fn veracruz_phase1_linear_regression_two_clients() {
    TestExecutor::test_template(
        LINEAR_REGRESSION_DUAL_POLICY,
        &vec![
            (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
            (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
        ],
        vec![
            (0, TestEvent::write_program(LINEAR_REGRESSION_WASM)),
            (1, TestEvent::write_data(LINEAR_REGRESSION_DATA)),
            (0, TestEvent::execute(LINEAR_REGRESSION_WASM)),
            (1, TestEvent::read_result("/output/linear-regression.dat")),
            (0, TestEvent::ShutDown),
        ],
    )
    .unwrap();
}

/// A test of veracruz using network communication using three sessions (one for program, one for data, and one for retrieval)
#[test]
fn veracruz_phase2_linear_regression_three_clients() {
    TestExecutor::test_template(
        LINEAR_REGRESSION_TRIPLE_POLICY,
        &vec![
            (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
            (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
            (RESULT_CLIENT_CERT, RESULT_CLIENT_KEY),
        ],
        vec![
            (0, TestEvent::write_program(LINEAR_REGRESSION_WASM)),
            (1, TestEvent::write_data(LINEAR_REGRESSION_DATA)),
            (0, TestEvent::execute(LINEAR_REGRESSION_WASM)),
            (1, TestEvent::read_result("/output/linear-regression.dat")),
            (2, TestEvent::read_result("/output/linear-regression.dat")),
            (0, TestEvent::ShutDown),
        ],
    )
    .unwrap();
}

/// A test of veracruz using network communication using four sessions
/// (one for program, one for the first data, and one for the second data and retrieval.)
#[test]
fn veracruz_phase2_intersection_set_sum_three_clients() {
    TestExecutor::test_template(
        INTERSECTION_SET_SUM_TRIPLE_POLICY,
        &vec![
            (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
            (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
            (RESULT_CLIENT_CERT, RESULT_CLIENT_KEY),
        ],
        vec![
            (
                0,
                TestEvent::write_program(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
            ),
            (
                1,
                TestEvent::write_data(INTERSECTION_SET_SUM_ADVERTISEMENT_DATA),
            ),
            (2, TestEvent::write_data(INTERSECTION_SET_SUM_CUSTOMER_DATA)),
            (
                0,
                TestEvent::execute(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
            ),
            (
                2,
                TestEvent::read_result("/output/intersection-set-sum.dat"),
            ),
            (0, TestEvent::ShutDown),
        ],
    )
    .unwrap();
}

/// A test of veracruz using network communication using three sessions
/// (one for program, one for the first data, and one for the second data and retrieval.)
#[test]
fn veracruz_phase2_string_edit_distance_three_clients() {
    TestExecutor::test_template(
        STRING_EDIT_DISTANCE_TRIPLE_POLICY,
        &vec![
            (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
            (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
            (RESULT_CLIENT_CERT, RESULT_CLIENT_KEY),
        ],
        vec![
            (0, TestEvent::write_program(STRING_EDIT_DISTANCE_WASM)),
            (1, TestEvent::write_data(STRING_1_DATA)),
            (2, TestEvent::write_data(STRING_2_DATA)),
            (0, TestEvent::execute(STRING_EDIT_DISTANCE_WASM)),
            (
                2,
                TestEvent::read_result("/output/string-edit-distance.dat"),
            ),
            (0, TestEvent::ShutDown),
        ],
    )
    .unwrap();
}

/// A test of veracruz using network communication using four sessions
/// (one for program, one for the first data, one for the second data, and one for retrieval.)
#[test]
fn veracruz_phase3_string_edit_distance_four_clients() {
    TestExecutor::test_template(
        STRING_EDIT_DISTANCE_QUADRUPLE_POLICY,
        &vec![
            (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
            (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
            (DATA_CLIENT_SECOND_CERT, DATA_CLIENT_SECOND_KEY),
            (RESULT_CLIENT_CERT, RESULT_CLIENT_KEY),
        ],
        vec![
            (0, TestEvent::write_program(STRING_EDIT_DISTANCE_WASM)),
            (1, TestEvent::write_data(STRING_1_DATA)),
            (2, TestEvent::write_data(STRING_2_DATA)),
            (0, TestEvent::execute(STRING_EDIT_DISTANCE_WASM)),
            (
                3,
                TestEvent::read_result("/output/string-edit-distance.dat"),
            ),
            (0, TestEvent::ShutDown),
        ],
    )
    .unwrap();
}

/// a test of veracruz using network communication using two parallel sessions
/// (one for program, one for data sending and retrieving)
#[test]
fn veracruz_phase4_linear_regression_two_clients_parallel() {
    let (_, policy_json, _) =
        read_policy(policy_dir(LINEAR_REGRESSION_PARALLEL_POLICY).as_path()).unwrap();
    let policy = Policy::from_json(&policy_json).unwrap();

    let _children = proxy_attestation_setup(
        policy.proxy_attestation_server_url().clone(),
        &env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()),
    );

    server_tls_loop(policy_json.clone());

    let policy_json_cloned = policy_json.clone();
    let client1_handle = thread::spawn(move || -> Result<()> {
        info!("### program provider start.");
        let mut client = veracruz_client::VeracruzClient::new(
            cert_key_dir(PROGRAM_CLIENT_CERT).as_path(),
            cert_key_dir(PROGRAM_CLIENT_KEY).as_path(),
            &policy_json_cloned,
        )?;
        let prog_path = program_dir(LINEAR_REGRESSION_WASM);
        info!("### program provider read binary.");
        let program_data = read_local_file(prog_path).unwrap();
        info!("### program provider send binary.");
        client.write_file("/program/linear-regression.wasm", &program_data)?;
        Result::<()>::Ok(())
    });

    let policy_json_cloned = policy_json.clone();
    let client2_handle = thread::spawn(move || -> Result<()> {
        info!("### data provider start.");
        let mut client = veracruz_client::VeracruzClient::new(
            cert_key_dir(DATA_CLIENT_CERT).as_path(),
            cert_key_dir(DATA_CLIENT_KEY).as_path(),
            &policy_json_cloned,
        )
        .unwrap();

        let data_filename = data_dir(LINEAR_REGRESSION_DATA);
        info!("### data provider read input.");
        let data = read_local_file(&data_filename).unwrap();
        info!("### data provider send input.");
        client.write_file("/input/linear-regression.dat", &data)?;
        Result::<()>::Ok(())
    });

    client1_handle.join().unwrap().unwrap();
    client2_handle.join().unwrap().unwrap();

    (|| -> Result<()> {
        info!("### third client start.");
        let mut client = veracruz_client::VeracruzClient::new(
            cert_key_dir(DATA_CLIENT_CERT).as_path(),
            cert_key_dir(DATA_CLIENT_KEY).as_path(),
            &policy_json,
        )
        .unwrap();

        client.request_compute("/program/linear-regression.wasm")?;
        client.read_file("/output/linear-regression.dat")?;
        info!("### data provider request shutdown.");
        client.request_shutdown()?;
        Ok(())
    })()
    .unwrap();
}

fn server_tls_loop(policy_json: String) {
    #[cfg(feature = "linux")]
    let platform_veracruz_server =
        linux_veracruz_server::server::VeracruzServerLinux::new(&policy_json).unwrap();
    #[cfg(feature = "nitro")]
    let platform_veracruz_server =
        nitro_veracruz_server::server::VeracruzServerNitro::new(&policy_json).unwrap();
    veracruz_server::server::server(&policy_json, platform_veracruz_server).unwrap()
}

/// Test states.
struct TestExecutor {
    // The json string of the policy
    policy_json: String,
    #[allow(dead_code)] // FIXME
    proxy_children: ProxyChildren,
}

impl TestExecutor {
    fn test_template<P: AsRef<str>, Q: AsRef<str>, K: AsRef<str>>(
        // Policy files
        policy_filename: P,
        // List of client's certificates and private keys
        client_cert_key_pairs: &[(Q, K)],
        events: Vec<(usize, TestEvent)>,
    ) -> Result<()> {
        Self::new(policy_dir(policy_filename))?.execute(
            &client_cert_key_pairs
                .iter()
                .map(|(cert, key)| (cert_key_dir(cert), cert_key_dir(key)))
                .collect::<Vec<_>>(),
            events,
        )?;
        Ok(())
    }

    fn new<P: AsRef<Path>>(policy_path: P) -> Result<Self> {
        let _ = env_logger::Builder::from_default_env()
            .write_style(env_logger::fmt::WriteStyle::Always)
            .is_test(true)
            .try_init();
        info!("Initialise proxy attestation server.");
        // Read the the policy
        let (policy, policy_json, _) = read_policy(policy_path)?;

        // start the proxy attestation server
        let proxy_children = proxy_attestation_setup(
            policy.proxy_attestation_server_url().clone(),
            &env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()),
        );

        Ok(TestExecutor {
            policy_json,
            proxy_children,
        })
    }

    /// Execute this test. Clients collectively execute as a block, driven by the `events`, in
    /// parallel with the server.
    fn execute<P: AsRef<Path>, Q: AsRef<Path>>(
        self,
        client_cert_key_pairs: &[(P, Q)],
        events: Vec<(usize, TestEvent)>,
    ) -> Result<()> {
        server_tls_loop(self.policy_json.clone());

        info!("Initialise clients.");
        // Initialise all clients
        let mut clients = Vec::new();
        for (cert, key) in client_cert_key_pairs.iter() {
            clients.push(
                veracruz_client::VeracruzClient::new(&cert, &key, &self.policy_json).unwrap(),
            );
        }

        // Process the events
        for (client_index, event) in events.iter() {
            let mut client = clients
                .get_mut(*client_index)
                .ok_or(anyhow!("cannot find client of index {}", client_index))
                .unwrap();
            info!("Process client{} event {:?}.", client_index, event);
            let time_init = Instant::now();
            Self::process_event(&mut client, &event)
                .map_err(|e| {
                    error!("Client of index {}: {:?}", client_index, e);
                    e
                })
                .unwrap();
            info!(
                "The event {:?} finished in {:?}.",
                event,
                time_init.elapsed()
            );
        }

        Ok(())
    }

    fn process_event(client: &mut VeracruzClient, event: &TestEvent) -> Result<()> {
        match event {
            TestEvent::CheckHash => {
                client.check_policy_hash()?;
                client.check_runtime_hash()?;
            }
            TestEvent::WriteFile(remote_path, local_path) => {
                let data = read_local_file(local_path)?;
                client.write_file(remote_path, &data)?;
            }
            TestEvent::AppendFile(remote_path, local_path) => {
                let data = read_local_file(local_path)?;
                client.append_file(remote_path, &data)?;
            }
            TestEvent::Execute(remote_path) => {
                client.request_compute(remote_path)?;
            }
            TestEvent::Pipeline(pipeline_id) => {
                client.request_pipeline(pipeline_id)?;
            }
            TestEvent::ReadFile(remote_path) => {
                let result = client.read_file(&remote_path)?;
                info!("receive data of bytes {}", result.len());
            }
            TestEvent::ShutDown => client.request_shutdown()?,
        };
        Ok(())
    }
}
