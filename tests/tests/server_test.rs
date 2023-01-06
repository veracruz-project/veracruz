//! Veracruz-server-specific tests
//!
//! One of the main integration tests for Veracruz, as a lot of material is
//! imported directly or indirectly via these tests.
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

use anyhow::{anyhow, Result};
use common::event::TestEvent;
use common::proxy_attestation_server::*;
use common::util::*;
use env_logger;
use log::{error, info};
use mbedtls::{alloc::List, x509::Certificate};
use policy_utils::{policy::Policy, Platform};
use std::{
    env,
    error::Error,
    io::{Read, Write},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
    vec::Vec,
};
use transport_protocol;
use veracruz_server::common::*;
use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;

// Policy files
const POLICY: &'static str = "single_client.json";
const CLIENT_CERT: &'static str = "client_cert.pem";
const CLIENT_KEY: &'static str = "client_key.pem";
const UNAUTHORIZED_CERT: &'static str = "data_client_cert.pem";
const UNAUTHORIZED_KEY: &'static str = "data_client_key.pem";
// Programs
const RANDOM_SOURCE_WASM: &'static str = "random-source.wasm";
const READ_FILE_WASM: &'static str = "read-file.wasm";
const LINEAR_REGRESSION_WASM: &'static str = "linear-regression.wasm";
const STRING_EDIT_DISTANCE_WASM: &'static str = "string-edit-distance.wasm";
const CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM: &'static str = "intersection-set-sum.wasm";
const PERSON_SET_INTERSECTION_WASM: &'static str = "private-set-intersection.wasm";
const LOGISTICS_REGRESSION_WASM: &'static str = "idash2017-logistic-regression.wasm";
const MACD_WASM: &'static str = "moving-average-convergence-divergence.wasm";
const INTERSECTION_SET_SUM_WASM: &'static str = "private-set-intersection-sum.wasm";
const FD_CREATE_RUST_WASM: &'static str = "fd-create.wasm";
const NUMBER_STREM_WASM: &'static str = "number-stream-accumulation.wasm";
const POSTCARD_NATIVE_WASM: &'static str = "postcard-native.wasm";
const POSTCARD_WASM: &'static str = "postcard-wasm.wasm";
const SORT_NUBMER_WASM: &'static str = "sort-numbers.wasm";
const RANDOM_U32_LIST_WASM: &'static str = "random-u32-list.wasm";
// Data
const LINEAR_REGRESSION_DATA: &'static str = "linear-regression.dat";
const INTERSECTION_SET_SUM_CUSTOMER_DATA: &'static str = "intersection-customer.dat";
const INTERSECTION_SET_SUM_ADVERTISEMENT_DATA: &'static str =
    "intersection-advertisement-viewer.dat";
const STRING_1_DATA: &'static str = "hello-world-1.dat";
const STRING_2_DATA: &'static str = "hello-world-2.dat";
const PERSON_SET_1_DATA: &'static str = "private-set-1.dat";
const PERSON_SET_2_DATA: &'static str = "private-set-2.dat";
const SINGLE_F64_DATA: &'static str = "number-stream-init.dat";
const POSTCARD_DATA: &'static str = "postcard.dat";
const F64_STREAM_PATH: &'static str = "number-stream/";
const LOGISTICS_REGRESSION_DATA_PATH: &'static str = "idash2017/";
const MACD_DATA_PATH: &'static str = "macd/";
const PRIVATE_SET_INTER_SUM_DATA_PATH: &'static str = "private-set-inter-sum/";
// default timeout
const TIME_OUT_SECS: u64 = 1200;

#[test]
/// Load a policy and initialize veracruz server (including runtime), and proxy attestation server.
/// Attestation happen during the veracruz runtime initialisation phase.
fn basic_init_destroy_enclave() {
    timeout(Duration::from_secs(TIME_OUT_SECS), || {
        let (policy, policy_json, _) = read_policy(policy_dir(POLICY)).unwrap();
        let _children = proxy_attestation_setup(
            policy.proxy_attestation_server_url().clone(),
            &env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()),
        );
        VeracruzServer::new(&policy_json).unwrap();
    })
}

#[test]
/// Load policy file and check if a new session tls can be opened
fn basic_new_session() {
    timeout(Duration::from_secs(TIME_OUT_SECS), || {
        let (policy, policy_json, _) = read_policy(policy_dir(POLICY)).unwrap();
        // start the proxy attestation server
        let _children = proxy_attestation_setup(
            policy.proxy_attestation_server_url().clone(),
            &env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()),
        );
        init_veracruz_server_and_tls_session(policy_json).unwrap();
    })
}

#[test]
/// Basic read from and write to files, and traverse directories.
fn basic_read_write_and_traverse() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(READ_FILE_WASM),
        TestEvent::write_data(STRING_1_DATA),
        TestEvent::execute(READ_FILE_WASM),
        TestEvent::read_result("/output/test/test.txt"),
        TestEvent::read_result("/output/hello-world-1.dat"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Generate random number.
fn basic_random_source() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(RANDOM_SOURCE_WASM),
        TestEvent::execute(RANDOM_SOURCE_WASM),
        TestEvent::read_result("/output/random.dat"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Custom external function `fd_create`
fn fd_create() {
    let events = vec![
        TestEvent::write_program(FD_CREATE_RUST_WASM),
        TestEvent::execute(FD_CREATE_RUST_WASM),
        TestEvent::read_result("/output/pass"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// A client attempts to execute a non-existent file
fn basic_execute_non_existent() {
    let events = vec![
        TestEvent::execute(RANDOM_SOURCE_WASM),
        TestEvent::read_result("/output/random.dat"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(
        POLICY,
        CLIENT_CERT,
        CLIENT_KEY,
        events,
        TIME_OUT_SECS,
        false,
    )
    .unwrap();
}

#[test]
/// A client attempts to read a non-existent file
fn basic_client_read_non_existent() {
    let events = vec![
        TestEvent::ReadFile(String::from("/output/random.dat")),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(
        POLICY,
        CLIENT_CERT,
        CLIENT_KEY,
        events,
        TIME_OUT_SECS,
        false,
    )
    .unwrap();
}

#[test]
/// A program attempts to read a non-existent file
fn basic_program_read_non_existent() {
    let events = vec![
        TestEvent::write_program(LINEAR_REGRESSION_WASM),
        TestEvent::execute(LINEAR_REGRESSION_WASM),
        TestEvent::ReadFile(String::from("/output/linear-regression.dat")),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(
        POLICY,
        CLIENT_CERT,
        CLIENT_KEY,
        events,
        TIME_OUT_SECS,
        false,
    )
    .unwrap();
}

#[test]
/// A client attempts to use an unauthorized key
fn basic_unauthorized_key() {
    let events = vec![
        TestEvent::write_program(RANDOM_SOURCE_WASM),
        TestEvent::execute(RANDOM_SOURCE_WASM),
        TestEvent::read_result("/output/random.dat"),
        TestEvent::ShutDown,
    ];

    let result = TestExecutor::test_template(
        POLICY,
        CLIENT_CERT,
        UNAUTHORIZED_KEY,
        events,
        TIME_OUT_SECS,
        false,
    );
    assert!(result.is_err(), "An error should occur");
}

#[test]
/// A client attempts to use an unauthorized certificate
fn basic_unauthorized_certificate() {
    let events = vec![
        TestEvent::write_program(RANDOM_SOURCE_WASM),
        TestEvent::execute(RANDOM_SOURCE_WASM),
        TestEvent::read_result("/output/random.dat"),
        TestEvent::ShutDown,
    ];

    let result = TestExecutor::test_template(
        POLICY,
        UNAUTHORIZED_CERT,
        CLIENT_KEY,
        events,
        TIME_OUT_SECS,
        false,
    );
    assert!(result.is_err(), "An error should occur");
}

#[test]
/// A unauthorized client attempts to connect the service
fn basic_unauthorized_certificate_key_pair() {
    let events = vec![
        TestEvent::write_program(RANDOM_SOURCE_WASM),
        TestEvent::execute(RANDOM_SOURCE_WASM),
        TestEvent::read_result("/output/random.dat"),
        TestEvent::ShutDown,
    ];

    let result = TestExecutor::test_template(
        POLICY,
        UNAUTHORIZED_CERT,
        UNAUTHORIZED_KEY,
        events,
        TIME_OUT_SECS,
        false,
    );
    assert!(result.is_err(), "An error should occur");
}

#[test]
/// Call an example native module.
fn basic_postcard_native_module() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(POSTCARD_NATIVE_WASM),
        TestEvent::write_data(POSTCARD_DATA),
        TestEvent::execute(POSTCARD_NATIVE_WASM),
        TestEvent::read_result("/output/postcard_native.txt"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Test for several rounds of appending data and executing program.
/// It sums up an initial f64 number and two streams of f64 numbers.
fn basic_number_accumulation_batch_process() {
    let mut events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(NUMBER_STREM_WASM),
        TestEvent::write_data(SINGLE_F64_DATA),
    ];
    events.append(&mut TestEvent::batch_process_events(
        data_dir(F64_STREAM_PATH),
        NUMBER_STREM_WASM,
        "/output/accumulation.dat",
    ));
    events.push(TestEvent::ShutDown);

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Test for several rounds of appending data and executing program.
/// It sums up an initial f64 number and two streams of f64 numbers.
fn basic_pipeline() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(RANDOM_U32_LIST_WASM),
        TestEvent::write_program(SORT_NUBMER_WASM),
        TestEvent::pipeline("0"),
        TestEvent::read_result("/output/sorted_numbers.txt"),
        TestEvent::ShutDown,
    ];
    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Integration test: linear regression.
/// Compute the gradient and intercept,
/// i.e. the LinearRegression struct, given a series of point in the
/// two-dimensional space.  Data sources: linear-regression, a vec of points
/// in two-dimensional space, represented by Vec<(f64, f64)>.
fn integration_linear_regression() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(LINEAR_REGRESSION_WASM),
        TestEvent::write_data(LINEAR_REGRESSION_DATA),
        TestEvent::execute(LINEAR_REGRESSION_WASM),
        TestEvent::read_result("/output/linear-regression.dat"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Integration test: intersection sum.
/// Intersection of two data sources and then the sum of the values in the intersection.
/// data sources: customer and advertisement, vecs of AdvertisementViewer and Customer
/// respectively.
/// ```no run
/// struct AdvertisementViewer { id: String }
/// struct Customer { id: String, total_spend: f64, }
/// ```
/// A standard two data source scenario, where the data provisioned in the
/// reversed order (data 1, then data 0)
fn integration_intersection_sum() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
        TestEvent::write_data(INTERSECTION_SET_SUM_CUSTOMER_DATA),
        TestEvent::write_data(INTERSECTION_SET_SUM_ADVERTISEMENT_DATA),
        TestEvent::execute(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
        TestEvent::read_result("/output/intersection-set-sum.dat"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Integration test: string-edit-distance.
/// Computing the string edit distance.
fn integration_string_edit_distance() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(STRING_EDIT_DISTANCE_WASM),
        TestEvent::write_data(STRING_1_DATA),
        TestEvent::write_data(STRING_2_DATA),
        TestEvent::execute(STRING_EDIT_DISTANCE_WASM),
        TestEvent::read_result("/output/string-edit-distance.dat"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Integration test: private set intersection.
/// Compute the intersection of two sets of persons.
/// data sources: two vecs of persons, representing by Vec<Person>
/// A standard two data sources scenario with attestation.
fn integration_private_set_intersection() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(PERSON_SET_INTERSECTION_WASM),
        TestEvent::write_data(PERSON_SET_1_DATA),
        TestEvent::write_data(PERSON_SET_2_DATA),
        TestEvent::execute(PERSON_SET_INTERSECTION_WASM),
        TestEvent::read_result("/output/private-set.dat"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Attempt to fetch result without enough stream data.
fn test_phase4_number_stream_accumulation_one_data_one_stream_with_attestation() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(NUMBER_STREM_WASM),
        TestEvent::write_data(SINGLE_F64_DATA),
        TestEvent::read_result("/output/accumulation.dat"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(
        POLICY,
        CLIENT_CERT,
        CLIENT_KEY,
        events,
        TIME_OUT_SECS,
        false,
    )
    .unwrap();
}

#[test]
/// Integration test: deserialize postcard encoding and reserialize to json.
fn integration_postcard_json() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(POSTCARD_WASM),
        TestEvent::write_data(POSTCARD_DATA),
        TestEvent::execute(POSTCARD_WASM),
        TestEvent::read_result("/output/postcard_wasm.txt"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Performance test: logistic regression.
/// Ref to https://github.com/kimandrik/IDASH2017.
/// data sources: idash2017/*.dat
fn performance_idash2017() {
    let mut events = vec![TestEvent::write_program(LOGISTICS_REGRESSION_WASM)];
    events.append(&mut TestEvent::write_all(
        data_dir(LOGISTICS_REGRESSION_DATA_PATH),
        "/input/idash2017/",
    ));
    events.append(&mut vec![
        TestEvent::CheckHash,
        TestEvent::execute(LOGISTICS_REGRESSION_WASM),
        // only read two outputs
        TestEvent::read_result("/output/idash2017/generate-data-0.dat"),
        TestEvent::read_result("/output/idash2017/generate-data-1.dat"),
        TestEvent::ShutDown,
    ]);

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Performance test: moving-average-convergence-divergence.
/// Ref: https://github.com/woonhulktin/HETSA.
/// data sources: macd/*.dat
fn performance_macd() {
    let mut events = vec![TestEvent::write_program(MACD_WASM)];
    events.append(&mut TestEvent::write_all(
        data_dir(MACD_DATA_PATH),
        "/input/macd/",
    ));
    events.append(&mut vec![
        TestEvent::CheckHash,
        TestEvent::execute(MACD_WASM),
        // only read two outputs
        TestEvent::read_result("/output/macd/generate-1000.dat"),
        TestEvent::ShutDown,
    ]);

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

#[test]
/// Performance test: intersection-sum.
/// data sources: private-set-inter-sum/*.dat
fn performance_set_intersection_sum() {
    let mut events = vec![TestEvent::write_program(INTERSECTION_SET_SUM_WASM)];
    events.append(&mut TestEvent::write_all(
        data_dir(PRIVATE_SET_INTER_SUM_DATA_PATH),
        "/input/private-set-inter-sum/",
    ));
    events.append(&mut vec![
        TestEvent::CheckHash,
        TestEvent::execute(INTERSECTION_SET_SUM_WASM),
        // only read two outputs
        TestEvent::read_result("/output/private-set-inter-sum/data-2000-0"),
        TestEvent::ShutDown,
    ]);

    TestExecutor::test_template(POLICY, CLIENT_CERT, CLIENT_KEY, events, TIME_OUT_SECS, true)
        .unwrap();
}

/// Test states.
struct TestExecutor {
    // The policy for the runtime.
    policy: Policy,
    // The hash of the policy, that is used in attestation.
    policy_hash: String,
    // Note that we only have one client in all tests.
    client_connection: mbedtls::ssl::Context<VeracruzSession>,
}

impl TestExecutor {
    /// This is the template. The template appends the path to the
    /// policy, and client certificate and key file, initialises the
    /// test veracruz server and a mock client accordingly, and then
    /// executes the test-case driven by mock client `events`. The
    /// function returns `Err(_)` if an error occurred before all the
    /// events were executed. Otherwise, the function panics if
    /// `expect_success` was set and one of the events did not return
    /// SUCCESS or if `expect_success` was not set and all of the
    /// events returned SUCCESS. Otherwise, it returns `Ok(())`.
    fn test_template<P: AsRef<str>, Q: AsRef<str>, K: AsRef<str>>(
        policy_filename: P,
        client_cert_filename: Q,
        client_key_filename: K,
        events: Vec<TestEvent>,
        timeout_sec: u64,
        expect_success: bool,
    ) -> Result<(), Box<dyn Error + 'static>> {
        let result = Self::new(
            policy_dir(policy_filename),
            cert_key_dir(client_cert_filename),
            cert_key_dir(client_key_filename),
        )?
        .execute(events, Duration::from_secs(timeout_sec))?;
        if result != expect_success {
            if expect_success {
                panic!("There was an unexpected failure");
            } else {
                panic!("A failure was expected");
            }
        }
        Ok(())
    }

    /// Create a new test executor. It initiates a server in a separate thread and creates a
    /// pair of channels between the main thread, who acts as a client, and the server thread.
    /// Those two channels simulate the network.
    fn new<P: AsRef<Path>, Q: AsRef<Path>, K: AsRef<Path>>(
        policy_path: P,
        client_cert_path: Q,
        client_key_path: K,
    ) -> Result<Self> {
        let _ = env_logger::Builder::from_default_env()
            .write_style(env_logger::fmt::WriteStyle::Always)
            .is_test(true)
            .try_init();
        info!("Initialise test configuration and proxy attestation server.");
        // Read the the policy
        let (policy, policy_json, policy_hash) = read_policy(policy_path)?;

        // start the proxy attestation server
        let _proxy_children = proxy_attestation_setup(
            policy.proxy_attestation_server_url().clone(),
            &env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()),
        );

        info!("Initialise Veracruz runtime.");
        // Create the server
        let mut veracruz_server =
            VeracruzServer::new(&policy_json).map_err(|e| anyhow!("{:?}", e))?;

        // Create the client tls session.
        let veracruz_session = veracruz_server
            .new_session()
            .map_err(|e| anyhow!("{:?}", e))?;

        info!("Initialise a client with its certificate and key.");
        // Create a fake client session which only ends to the simulated connecting channel.
        let client_connection = create_client_test_connection(
            client_cert_path,
            client_key_path,
            &policy.ciphersuite(),
            veracruz_session.clone(),
        )?;

        Ok(TestExecutor {
            policy,
            policy_hash,
            client_connection,
        })
    }

    /// Execute this test. The client sends messages though the channel to the server
    /// thread driven by `events`. It consumes the ownership of `self`,
    /// because it will join server thread at the end.
    fn execute(mut self, events: Vec<TestEvent>, _timeout: Duration) -> anyhow::Result<bool> {
        let mut error_occurred = false;

        // process test events
        for event in events.iter() {
            info!("Process event {:?}.", event);
            let time_init = Instant::now();
            let response = self.process_event(&event).map_err(|e| {
                error!("Client: {:?}", e);
                e
            })?;
            if response.get_status() != transport_protocol::ResponseStatus::SUCCESS {
                error_occurred = true;
            }
            info!(
                "The event {:?} finished with response status {:?} in {:?}.",
                event,
                response.get_status(),
                time_init.elapsed()
            );
        }

        Ok(!error_occurred)
    }

    fn process_event(
        &mut self,
        event: &TestEvent,
    ) -> Result<transport_protocol::RuntimeManagerResponse> {
        let response = match event {
            TestEvent::CheckHash => {
                let response = self.check_policy_hash()?;
                self.check_runtime_manager_hash()?;
                response
            }
            TestEvent::WriteFile(remote_path, local_path) => {
                self.write_file(&remote_path, local_path)?
            }
            TestEvent::AppendFile(remote_path, local_path) => {
                self.append_file(&remote_path, local_path)?
            }
            TestEvent::Execute(remote_path) => self.execute_program(&remote_path)?,
            TestEvent::Pipeline(pipeline_id) => self.execute_pipeline(&pipeline_id)?,
            TestEvent::ReadFile(remote_path) => self.read_file(&remote_path)?,
            TestEvent::ShutDown => self.shutdown()?,
        };
        Ok(transport_protocol::parse_runtime_manager_response(
            None, &response,
        )?)
    }

    fn check_policy_hash(&mut self) -> Result<Vec<u8>> {
        let serialized_request_policy_hash = transport_protocol::serialize_request_policy_hash()
            .map_err(|e| {
                anyhow!(
                    "Failed to serialize request for policy hash.  Error produced: {:?}.",
                    e
                )
            })?;

        let response = self.client_send(&serialized_request_policy_hash[..])?;
        let parsed_response = transport_protocol::parse_runtime_manager_response(None, &response)?;
        let status = parsed_response.get_status();

        if status != transport_protocol::ResponseStatus::SUCCESS {
            return Err(anyhow!("Received non-Success status: {:?}.", status).into());
        }
        let received_hash = std::str::from_utf8(&parsed_response.get_policy_hash().data)?;
        info!("Received {:?} as hash.", received_hash);
        if received_hash != self.policy_hash {
            return Err(anyhow!(
                "Hash does not match expected hash ({:?}).",
                self.policy_hash
            )
            .into());
        }
        Ok(response)
    }

    /// Check the runtime manager hash. This function assumes that
    /// `self.client_connection` handshake completes. Any previous invocation of `self.client_send`
    /// will achieve this status, e.g. `self.check_policy_hash`
    fn check_runtime_manager_hash(&mut self) -> Result<()> {
        // Set up the test target platform
        let target_platform = if cfg!(feature = "linux") {
            Platform::Linux
        } else if cfg!(feature = "nitro") {
            Platform::Nitro
        } else if cfg!(feature = "icecap") {
            Platform::IceCap
        } else {
            panic!("Unknown platform.");
        };

        // Get all the certificates. Assume that the handshake completes.
        let certs = self.client_connection.peer_cert()?;
        if certs.iter().count() != 1 {
            return Err(anyhow!("no peer certificates"));
        }
        let cert = certs
            .ok_or(anyhow!("unexpected certificate"))?
            .iter()
            .nth(0)
            .ok_or(anyhow!("unexpected certificate"))?;
        let extensions = cert.extensions()?;
        // check for OUR extension
        match veracruz_utils::find_extension(extensions, &VERACRUZ_RUNTIME_HASH_EXTENSION_ID) {
            None => Err(anyhow!("Our certificate extension is not present.")),
            Some(data) => {
                info!("Certificate extension found.");
                if compare_policy_hash(&data, &self.policy, &target_platform) {
                    Ok(())
                } else {
                    Err(anyhow!("None of the runtime manager hashes matched."))
                }
            }
        }
    }

    #[inline]
    fn write_file<P: AsRef<Path>>(&mut self, remote_path: &str, local_path: P) -> Result<Vec<u8>> {
        // Read the local data and create a protobuf message.
        let data = read_local_file(local_path)?;
        let serialized_data = transport_protocol::serialize_write_file(&data, remote_path)?;
        self.client_send(&serialized_data[..])
    }

    #[inline]
    fn append_file<P: AsRef<Path>>(&mut self, remote_path: &str, local_path: P) -> Result<Vec<u8>> {
        // Read the local data and create a protobuf message.
        let data = read_local_file(local_path)?;
        let serialized_data = transport_protocol::serialize_append_file(&data, remote_path)?;
        self.client_send(&serialized_data[..])
    }

    #[inline]
    fn execute_program(&mut self, remote_path: &str) -> Result<Vec<u8>> {
        self.client_send(&transport_protocol::serialize_request_result(remote_path)?[..])
    }

    #[inline]
    fn execute_pipeline(&mut self, pipeline_id: &str) -> Result<Vec<u8>> {
        self.client_send(&transport_protocol::serialize_request_pipeline(pipeline_id)?[..])
    }

    #[inline]
    fn read_file(&mut self, remote_path: &str) -> Result<Vec<u8>> {
        self.client_send(&transport_protocol::serialize_read_file(remote_path)?[..])
    }

    #[inline]
    fn shutdown(&mut self) -> Result<Vec<u8>> {
        self.client_send(&transport_protocol::serialize_request_shutdown()?[..])
    }

    /// The client sends TLS packages via the simulated channel.
    fn client_send(&mut self, send_data: &[u8]) -> Result<Vec<u8>> {
        let connection = &mut self.client_connection;
        connection.write_all(&send_data)?;
        const PREFLEN: usize = transport_protocol::LENGTH_PREFIX_SIZE;
        let mut length_buffer = [0; PREFLEN];
        connection.read_exact(&mut length_buffer)?;
        let length = PREFLEN + u64::from_be_bytes(length_buffer) as usize;
        let mut response = length_buffer.to_vec();
        response.resize(length, 0);
        connection.read_exact(&mut response[PREFLEN..length])?;
        Ok(response)
    }
}

/// Auxiliary function: initialise the Veracruz server from policy and open a tls session
fn init_veracruz_server_and_tls_session<T: AsRef<str>>(
    policy_json: T,
) -> Result<(VeracruzServer, VeracruzSession)> {
    let mut veracruz_server =
        VeracruzServer::new(policy_json.as_ref()).map_err(|e| anyhow!("{:?}", e))?;

    let session = veracruz_server
        .new_session()
        .map_err(|e| anyhow!("{:?}", e))?;
    Ok((veracruz_server, session))
}

fn compare_policy_hash(received: &[u8], policy: &Policy, platform: &Platform) -> bool {
    if cfg!(feature = "debug") {
        // don't check hash because the received hash might be zeros (for nitro, for example)
        return true;
    } else {
        let expected = match policy.runtime_manager_hash(platform) {
            Err(_) => return false,
            Ok(data) => data,
        };
        let expected_bytes = match hex::decode(expected) {
            Err(_) => return false,
            Ok(bytes) => bytes,
        };

        info!("Comparing runtime manager hash {:?} (from policy) against {:?} (received) for platform {:?}.", expected_bytes, received, platform);

        if &received[..] != expected_bytes.as_slice() {
            info!("Runtime manager hash does not match.");

            return false;
        } else {
            info!("Runtime manager hash matches.");

            return true;
        }
    }
}

fn create_client_test_connection<P: AsRef<Path>, Q: AsRef<Path>>(
    client_cert_filename: P,
    client_key_filename: Q,
    ciphersuite_str: &str,
    session: VeracruzSession,
) -> Result<mbedtls::ssl::Context<VeracruzSession>> {
    let client_cert = read_cert_file(client_cert_filename)?;

    let client_priv_key = read_priv_key_file(client_key_filename)?;

    let proxy_service_cert = {
        let mut data = std::fs::read(cert_key_dir(CA_CERT))?;
        data.push(b'\0');
        let certs = Certificate::from_pem_multiple(&data)?;
        if certs.iter().count() < 1 {
            Err(anyhow!("no certificates"))
        } else {
            Ok(certs)
        }
    }?;

    let mut root_store = List::new();
    root_store.append(proxy_service_cert);

    let mut config = mbedtls::ssl::Config::new(
        mbedtls::ssl::config::Endpoint::Client,
        mbedtls::ssl::config::Transport::Stream,
        mbedtls::ssl::config::Preset::Default,
    );
    config.set_min_version(mbedtls::ssl::config::Version::Tls1_3)?;
    config.set_max_version(mbedtls::ssl::config::Version::Tls1_3)?;
    let policy_ciphersuite = veracruz_utils::lookup_ciphersuite(ciphersuite_str)
        .ok_or_else(|| anyhow!("invalid ciphersuite"))?;
    let cipher_suites: Vec<i32> = vec![policy_ciphersuite.into(), 0];
    config.set_ciphersuites(Arc::new(cipher_suites));
    let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
    let rng = Arc::new(mbedtls::rng::CtrDrbg::new(entropy, None)?);
    config.set_rng(rng);
    config.set_ca_list(Arc::new(root_store), None);
    config.push_cert(Arc::new(client_cert), Arc::new(client_priv_key))?;
    let mut ctx = mbedtls::ssl::Context::new(Arc::new(config));
    let _ = ctx.establish(session, None);
    Ok(ctx)
}

fn read_cert_file<P: AsRef<Path>>(filename: P) -> Result<List<Certificate>> {
    let mut buffer = std::fs::read(filename)?;
    buffer.push(b'\0');
    let cert_vec = Certificate::from_pem_multiple(&buffer)?;
    if cert_vec.iter().count() == 1 {
        Ok(cert_vec)
    } else {
        Err(anyhow!("certs.len() is zero"))
    }
}

fn read_priv_key_file<P: AsRef<Path>>(filename: P) -> Result<mbedtls::pk::Pk> {
    let mut buffer = std::fs::read(filename)?;
    buffer.push(b'\0');
    let pkey_vec = mbedtls::pk::Pk::from_private_key(
        &mut mbedtls::rng::CtrDrbg::new(Arc::new(mbedtls::rng::OsEntropy::new()), None)?,
        &buffer,
        None,
    )?;
    Ok(pkey_vec)
}
