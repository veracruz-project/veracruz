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
#[cfg(feature = "linux")]
use linux_veracruz_server::server::VeracruzServerLinux as VeracruzServerEnclave;
use log::{error, info};
use mbedtls::{alloc::List, x509::Certificate};
#[cfg(feature = "nitro")]
use nitro_veracruz_server::server::VeracruzServerNitro as VeracruzServerEnclave;
use policy_utils::{policy::Policy, Platform};
use std::{
    env,
    error::Error,
    io::{Read, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Receiver, Sender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
    vec::Vec,
};
use transport_protocol;
use veracruz_server::common::*;
use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;

// Policy files
const POLICY: &'static str = "single_client.json";
const POLICY_POSTCARD_NATIVE: &'static str = "single_client_postcard_native.json";
const POLICY_AESCTR_NATIVE: &'static str = "single_client_aesctr_native.json";
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
const AESCTR_NATIVE_WASM: &'static str = "aesctr-native.wasm";
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
        VeracruzServerEnclave::new(&policy_json).unwrap();
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
/// Test AES native module.
fn aesctr_native_module() {
    let events = vec![
        TestEvent::CheckHash,
        TestEvent::write_program(AESCTR_NATIVE_WASM),
        TestEvent::execute(AESCTR_NATIVE_WASM),
        TestEvent::read_result("/output/aesctr_native_pass.txt"),
        TestEvent::ShutDown,
    ];

    TestExecutor::test_template(
        POLICY_AESCTR_NATIVE,
        CLIENT_CERT,
        CLIENT_KEY,
        events,
        TIME_OUT_SECS,
        true,
    )
    .unwrap();
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

    TestExecutor::test_template(
        POLICY_POSTCARD_NATIVE,
        CLIENT_CERT,
        CLIENT_KEY,
        events,
        TIME_OUT_SECS,
        true,
    )
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
    // The hash of the policy, that is used in attestation
    policy_hash: String,
    // The emulated TLS connect from client to server.
    client_tls_receiver: Receiver<Vec<u8>>,
    client_tls_sender: Sender<(u32, Vec<u8>)>,
    // Paths to client certification and private key.
    // Note that we only have one client in all tests.
    client_connection: mbedtls::ssl::Context<InsecureConnection>,
    client_connection_id: u32,
    // Read and write buffers shared with InsecureConnection.
    shared_buffers: Arc<Mutex<Buffers>>,
    // A alive flag. This is to solve the problem where the server thread still in loop while
    // client thread is terminated.
    alive_flag: Arc<AtomicBool>,
    // Hold the server thread. The test will join the thread in the end to check the server
    // state.
    server_thread: JoinHandle<Result<()>>,
}

struct Buffers {
    // Read buffer used by mbedtls for cyphertext.
    read_buffer: Vec<u8>,
    // Write buffer used by mbedtls for cyphertext.
    write_buffer: Option<Vec<u8>>,
}

/// This is the structure given to mbedtls and used for reading and
/// writing cyphertext, using the standard Read and Write traits.
struct InsecureConnection {
    // Read and write buffers shared with Session.
    shared_buffers: Arc<Mutex<Buffers>>,
}

// To convert any error to a std::io error:
fn std_err(error_text: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, error_text)
}

impl Read for InsecureConnection {
    fn read(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        // Return as much data from the read_buffer as fits.
        let mut shared_buffers = self
            .shared_buffers
            .lock()
            .map_err(|_| std_err("lock failed"))?;
        let n = std::cmp::min(data.len(), shared_buffers.read_buffer.len());
        if n == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "InsecureConnection Read",
            ))
        } else {
            data[0..n].clone_from_slice(&shared_buffers.read_buffer[0..n]);
            shared_buffers.read_buffer = shared_buffers.read_buffer[n..].to_vec();
            Ok(n)
        }
    }
}

impl Write for InsecureConnection {
    fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        // Append to write buffer.
        let mut shared_buffers = self
            .shared_buffers
            .lock()
            .map_err(|_| std_err("lock failed"))?;
        match &mut shared_buffers.write_buffer {
            None => shared_buffers.write_buffer = Some(data.to_vec()),
            Some(x) => x.extend_from_slice(data),
        }
        // Return value to indicate that we handled all the data.
        Ok(data.len())
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
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

        info!("Create simulated connection channels.");
        // Create two channel, simulating the connecting channels.
        let (server_tls_sender, client_tls_receiver) = channel::<Vec<u8>>();
        let (client_tls_sender, server_tls_receiver) = channel::<(u32, Vec<u8>)>();

        let shared_buffers = Arc::new(Mutex::new(Buffers {
            read_buffer: vec![],
            write_buffer: None,
        }));

        info!("Initialise a client with its certificate and key.");
        // Create a fake client session which only ends to the simulated connecting channel.
        let client_connection = create_client_test_connection(
            client_cert_path,
            client_key_path,
            &policy.ciphersuite(),
            Arc::clone(&shared_buffers),
        )?;

        info!("Initialise Veracruz runtime.");
        // Create the server
        let mut platform_veracruz_server = VeracruzServerEnclave::new(&policy_json)
            .map_err(|e| anyhow!("{:?}", e))
            .map_err(|e| {
                println!("VeracruzServerEnclave::new failed:{:?}", e);
                anyhow!("{:?}", e)
            })?;

        // Create the client tls session. Note that we need the session id.
        let client_connection_id =
            veracruz_server::server::new_tls_session(&mut platform_veracruz_server)
                .map_err(|e| anyhow!("{:?}", e))?;
        if client_connection_id == 0 {
            return Err(anyhow!("client session id is zero"));
        }

        info!("Spawn server thread.");
        // Create the sever loop, it is the end of the previous created channels.
        let alive_flag = Arc::new(AtomicBool::new(true));
        let init_flag = Arc::new(AtomicBool::new(false));
        // Create a clone which passes to server thread.
        let alive_flag_clone = alive_flag.clone();
        let init_flag_clone = init_flag.clone();
        let server_thread = thread::spawn(move || {
            if let Err(e) = TestExecutor::simulated_server(
                &mut platform_veracruz_server,
                server_tls_sender,
                server_tls_receiver,
                alive_flag_clone.clone(),
                init_flag_clone,
            ) {
                alive_flag_clone.store(false, Ordering::SeqCst);
                Err(e)
            } else {
                Ok(())
            }
        });
        info!("A new test executor is created.");

        // Block until the init_flag is set by the server thread.
        while !init_flag.load(Ordering::SeqCst) {}

        Ok(TestExecutor {
            policy,
            policy_hash,
            client_connection,
            client_connection_id,
            shared_buffers,
            client_tls_sender,
            client_tls_receiver,
            alive_flag,
            server_thread,
        })
    }

    /// This function simulating a Veracruz server, it should run on a separate thread.
    fn simulated_server<T: VeracruzServer + Send + Sync + ?Sized>(
        platform_veracruz_server: &mut T,
        sender: Sender<Vec<u8>>,
        receiver: Receiver<(u32, Vec<u8>)>,
        test_alive_flag: Arc<AtomicBool>,
        test_init_flag: Arc<AtomicBool>,
    ) -> Result<()> {
        info!("Server: simulated server loop starts...");

        test_init_flag.store(true, Ordering::SeqCst);

        while test_alive_flag.load(Ordering::SeqCst) {
            let received = receiver.recv();
            let (session_id, received_buffer) = received.map_err(|e| anyhow!("Server: {:?}", e))?;
            info!(
                "Server: receive {} byte(s) on session ID {}.",
                received_buffer.len(),
                session_id
            );

            let (veracruz_active_flag, output_data_option) = veracruz_server::server::tls_data(
                session_id,
                received_buffer,
                platform_veracruz_server,
            )
            .map_err(|e| {
                // This point has a high chance to fail.
                error!("Veracruz Server: {:?}", e);
                e
            })
            .map_err(|e| anyhow!("{:?}", e))?;

            // At least send an empty message, this notifies the client.
            let output_data = output_data_option.unwrap_or_else(|| vec![vec![]]);

            for output in output_data.iter() {
                sender.send(output.clone()).map_err(|e| {
                    anyhow!(
                        "Failed to send data on TX channel.  Error produced: {:?}.",
                        e
                    )
                })?;
            }

            if !veracruz_active_flag {
                info!("Veracruz server TLS loop dying due to lack of TLS data.");
                return Ok(());
            }
        }

        // The server should not reach here.
        Err(anyhow!(
            "VeracruzServer TLS loop dieing due to no activity..."
        ))
    }

    /// Execute this test. The client sends messages though the channel to the server
    /// thread driven by `events`. It consumes the ownership of `self`,
    /// because it will join server thread at the end.
    fn execute(mut self, events: Vec<TestEvent>, timeout: Duration) -> anyhow::Result<bool> {
        // Spawn a thread that will send the timeout signal by killing alive flag.
        let alive_flag_clone = self.alive_flag.clone();
        thread::spawn(move || {
            thread::sleep(timeout);
            if alive_flag_clone.load(Ordering::SeqCst) {
                error!(
                    "--->>> Force timeout. It is very likely to trigger error on the test. <<<---"
                );
            }
            alive_flag_clone.store(false, Ordering::SeqCst);
        });

        let mut error_occurred = false;

        // process test events
        for event in events.iter() {
            info!("Process event {:?}.", event);
            let time_init = Instant::now();
            let response = self.process_event(&event).map_err(|e| {
                error!("Client: {:?}", e);
                self.alive_flag.store(false, Ordering::SeqCst);
                e
            })?;
            let status = response.status.enum_value_or_default();
            if status != transport_protocol::ResponseStatus::SUCCESS {
                error_occurred = true;
            }
            info!(
                "The event {:?} finished with response status {:?} in {:?}.",
                event,
                status,
                time_init.elapsed()
            );
        }

        // Wait the server to finish.
        self.server_thread
            .join()
            .map_err(|e| anyhow!("server thread failed with error {:?}", e))?
            .map_err(|e| anyhow!("{:?}", e))?;
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
        let status = parsed_response.status.enum_value_or_default();

        if status != transport_protocol::ResponseStatus::SUCCESS {
            return Err(anyhow!("Received non-Success status: {:?}.", status).into());
        }
        let received_hash = std::str::from_utf8(&parsed_response.policy_hash().data)?;
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
        info!(
            "Client: client send with length of data {:?}",
            send_data.len()
        );
        let connection = &mut self.client_connection;
        let mut write_all_succeeded = false;
        while self.alive_flag.load(Ordering::SeqCst) {
            // connection.write_all
            if !write_all_succeeded {
                match connection.write_all(&send_data[..]) {
                    Ok(()) => write_all_succeeded = true,
                    Err(err) => {
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            ()
                        } else {
                            return Err(anyhow!(
                                "Failed to send all data.  Error produced: {:?}.",
                                err
                            ));
                        }
                    }
                }
            }

            // write_buffer.take
            let taken = self
                .shared_buffers
                .lock()
                .map_err(|_| anyhow!("lock failed"))?
                .write_buffer
                .take();
            match taken {
                None => (),
                Some(output) => {
                    // client_tls_sender.send
                    self.client_tls_sender
                        .send((self.client_connection_id, output))
                        .map_err(|e| {
                            anyhow!(
                                "Failed to send data on TX channel. Error produced: {:?}.",
                                e
                            )
                        })?;

                    // client_tls_receiver.recv
                    let received = self.client_tls_receiver.recv()?;

                    // read_buffer.extend_from_slice
                    self.shared_buffers
                        .lock()
                        .map_err(|_| anyhow!("lock failed"))?
                        .read_buffer
                        .extend_from_slice(&received);
                }
            }

            // connection.read_to_end
            let mut received_buffer: Vec<u8> = Vec::new();
            let res = connection.read_to_end(&mut received_buffer);
            if received_buffer.len() > 0 {
                return Ok(received_buffer);
            }
            match res {
                Ok(_) => (),
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        ()
                    } else {
                        return Err(anyhow!(
                            "Failed to read data to end.  Error produced: {:?}.",
                            err
                        ));
                    }
                }
            }
        }

        // If reach here, it means the server crashed.
        Err(anyhow!("Terminate due to server crash"))
    }
}

/// Auxiliary function: initialise the Veracruz server from policy and open a tls session
fn init_veracruz_server_and_tls_session<T: AsRef<str>>(
    policy_json: T,
) -> Result<(VeracruzServerEnclave, u32)> {
    let mut platform_veracruz_server =
        VeracruzServerEnclave::new(policy_json.as_ref()).map_err(|e| anyhow!("{:?}", e))?;

    let session_id = veracruz_server::server::new_tls_session(&mut platform_veracruz_server)
        .map_err(|e| anyhow!("{:?}", e))?;
    if session_id != 0 {
        Ok((platform_veracruz_server, session_id))
    } else {
        Err(anyhow!("Session ID cannot be zero").into())
    }
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
    shared_buffers: Arc<Mutex<Buffers>>,
) -> Result<mbedtls::ssl::Context<InsecureConnection>> {
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
    config.set_min_version(mbedtls::ssl::config::Version::Tls13)?;
    config.set_max_version(mbedtls::ssl::config::Version::Tls13)?;
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
    let conn = InsecureConnection { shared_buffers };
    let _ = ctx.establish(conn, None);
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
