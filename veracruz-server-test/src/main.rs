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

pub fn main() -> Result<(), String> {
    Ok(())
}

mod tests {
    use actix_rt::System;
    use either::{Left, Right};
    use env_logger;
    use log::{error, info};
    use policy_utils::{policy::Policy, Platform};
    use proxy_attestation_server;
    use rustls_pemfile;
    use std::{
        convert::TryFrom,
        env::{self, VarError},
        error::Error,
        fs::File,
        io::{Read, Write},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc::{channel, Receiver, Sender},
            Arc, Once,
        },
        thread,
        thread::JoinHandle,
        time::{Duration, Instant},
        vec::Vec,
    };
    use transport_protocol;
    use veracruz_server::veracruz_server::*;
    #[cfg(feature = "icecap")]
    use veracruz_server::VeracruzServerIceCap as VeracruzServerEnclave;
    #[cfg(feature = "linux")]
    use veracruz_server::VeracruzServerLinux as VeracruzServerEnclave;
    #[cfg(feature = "nitro")]
    use veracruz_server::VeracruzServerNitro as VeracruzServerEnclave;
    use veracruz_utils::sha256::sha256;
    use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;

    // Policy files
    const POLICY: &'static str = "single_client.json";
    const CA_CERT: &'static str = "CACert.pem";
    const CA_KEY: &'static str = "CAKey.pem";
    const CLIENT_CERT: &'static str = "client_rsa_cert.pem";
    const CLIENT_KEY: &'static str = "client_rsa_key.pem";
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

    static PROXY_ATTESTATION_SETUP: Once = Once::new();

    /// Add the policy directory, reading from environment variable `$VERACRUZ_POLICY_DIR` or using the
    /// default `test-collateral`.
    pub fn policy_dir<T: AsRef<str>>(filename: T) -> PathBuf {
        PathBuf::from(env::var("VERACRUZ_POLICY_DIR").unwrap_or("../test-collateral".to_string()))
            .join(filename.as_ref())
    }

    /// Add the certificate and key directory, reading from environment variable `$VERACRUZ_TRUST_DIR`
    /// or using the default `test-collateral`.
    pub fn cert_key_dir<T: AsRef<str>>(filename: T) -> PathBuf {
        PathBuf::from(env::var("VERACRUZ_TRUST_DIR").unwrap_or("../test-collateral".to_string()))
            .join(filename.as_ref())
    }

    /// Add the program directory, reading from environment variable `$VERACRUZ_PROGRAM_DIR`
    /// or using the default `test-collateral`.
    pub fn program_dir<T: AsRef<str>>(filename: T) -> PathBuf {
        PathBuf::from(env::var("VERACRUZ_PROGRAM_DIR").unwrap_or("../test-collateral".to_string()))
            .join(filename.as_ref())
    }

    /// Add the data directory, reading from environment variable `$VERACRUZ_DATA_DIR`
    /// or using the default `test-collateral`.
    pub fn data_dir<T: AsRef<str>>(filename: T) -> PathBuf {
        PathBuf::from(env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()))
            .join(filename.as_ref())
    }

    /// Add path prefix, `$REMOTE_PROGRAM_DIR` or the default `/program/`, to the program `filename`.
    pub fn runtime_program_dir<T: AsRef<str>>(filename: T) -> String {
        let mut path_prefix = env::var("REMOTE_PROGRAM_DIR").unwrap_or("/program/".to_string());
        path_prefix.push_str(filename.as_ref());
        path_prefix
    }

    /// Add path prefix, `$REMOTE_DATA_DIR` or the default `/input/`, to the program `filename`.
    pub fn runtime_data_dir<T: AsRef<str>>(filename: T) -> String {
        let mut path_prefix = env::var("REMOTE_DATA_DIR").unwrap_or("/input/".to_string());
        path_prefix.push_str(filename.as_ref());
        path_prefix
    }

    /// A wrapper to force tests to panic after a timeout.
    ///
    /// Note this is overrideable with the VERACRUZ_TEST_TIMEOUT environment
    /// variable, which provides a timeout in seconds
    pub fn timeout<R: Send + 'static, F: (FnOnce() -> R) + Send + 'static>(
        timeout: Duration,
        f: F,
    ) -> R {
        let timeout = match env::var("VERACRUZ_TEST_TIMEOUT")
            .map_err(Left)
            .and_then(|timeout| timeout.parse::<u64>().map_err(Right))
        {
            Ok(val) => Duration::from_secs(val),
            Err(Left(VarError::NotPresent)) => timeout,
            Err(err) => panic!("Couldn't parse VERACRUZ_TEST_TIMEOUT: {:?}", err),
        };

        // based on https://github.com/rust-lang/rfcs/issues/2798#issuecomment-552949300
        let (done_tx, done_rx) = channel();
        let thread = thread::spawn(move || {
            let r = f();
            done_tx.send(()).unwrap();
            r
        });

        match done_rx.recv_timeout(timeout) {
            Ok(_) => thread.join().expect("thread panicked"),
            Err(_) => panic!(
                "timeout after {:?}, specify VERACRUZ_TEST_TIMEOUT to override",
                timeout
            ),
        }
    }

    pub fn proxy_attestation_setup(proxy_attestation_server_url: String) {
        PROXY_ATTESTATION_SETUP.call_once(|| {
            info!("Proxy attestation server: initialize.");

            env_logger::init();

            let _main_loop_handle = std::thread::spawn(|| {
                let sys = System::new();
                info!(
                    "spawned thread calling server with url:{:?}",
                    proxy_attestation_server_url
                );
                let debug_flag = if cfg!(feature = "debug") { true } else { false };
                let server = proxy_attestation_server::server::server(
                    proxy_attestation_server_url,
                    cert_key_dir(CA_CERT).as_path(),
                    cert_key_dir(CA_KEY).as_path(),
                    debug_flag,
                )
                .unwrap();
                sys.block_on(server).unwrap();
            });
        });
        // Sleep to wait for the proxy attestation server to start
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    #[test]
    /// Load a policy and initialize veracruz server (including runtime), and proxy attestation server.
    /// Attestation happen during the veracruz runtime initialisation phase.
    fn basic_init_destroy_enclave() {
        timeout(Duration::from_secs(TIME_OUT_SECS), || {
            let (policy, policy_json, _) = read_policy(policy_dir(POLICY)).unwrap();
            proxy_attestation_setup(policy.proxy_attestation_server_url().clone());
            VeracruzServerEnclave::new(&policy_json).unwrap();
        })
    }

    #[test]
    /// Load policy file and check if a new session tls can be opened
    fn basic_new_session() {
        timeout(Duration::from_secs(TIME_OUT_SECS), || {
            let (policy, policy_json, _) = read_policy(policy_dir(POLICY)).unwrap();
            // start the proxy attestation server
            proxy_attestation_setup(policy.proxy_attestation_server_url().clone());
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

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
        .unwrap();
    }

    #[test]
    /// Generate random number.
    fn basic_random_source() {
        let events = vec![
            TestEvent::write_program(RANDOM_SOURCE_WASM),
            TestEvent::execute(RANDOM_SOURCE_WASM),
            TestEvent::read_result("/output/random.dat"),
            TestEvent::ShutDown,
        ];

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
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

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
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

        let result = TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// A client attempts to read a non-existent file
    fn basic_client_read_non_existent() {
        let events = vec![
            TestEvent::ReadFile(String::from("/output/random.dat")),
            TestEvent::ShutDown,
        ];

        let result = TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        );
        assert!(result.is_err(), "An error should occur");
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

        let result = TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        );
        assert!(result.is_err(), "An error should occur");
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
            Duration::from_secs(TIME_OUT_SECS),
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
            Duration::from_secs(TIME_OUT_SECS),
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
            Duration::from_secs(TIME_OUT_SECS),
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Call an example native module.
    fn basic_postcard_native_module() {
        let events = vec![
            TestEvent::write_program(POSTCARD_NATIVE_WASM),
            TestEvent::write_data(POSTCARD_DATA),
            TestEvent::execute(POSTCARD_NATIVE_WASM),
            TestEvent::read_result("/output/postcard_native.txt"),
            TestEvent::ShutDown,
        ];

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
        .unwrap();
    }

    #[test]
    /// Test for several rounds of appending data and executing program.
    /// It sums up an initial f64 number and two streams of f64 numbers.
    fn basic_number_accumulation_batch_process() {
        let mut events = vec![
            TestEvent::write_program(NUMBER_STREM_WASM),
            TestEvent::write_data(SINGLE_F64_DATA),
        ];
        events.append(&mut TestEvent::batch_process_events(
            data_dir(F64_STREAM_PATH),
            NUMBER_STREM_WASM,
            "/output/accumulation.dat",
        ));
        events.push(TestEvent::ShutDown);

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
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
            TestEvent::write_program(LINEAR_REGRESSION_WASM),
            TestEvent::write_data(LINEAR_REGRESSION_DATA),
            TestEvent::execute(LINEAR_REGRESSION_WASM),
            TestEvent::read_result("/output/linear-regression.dat"),
            TestEvent::ShutDown,
        ];

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
        .unwrap();
    }

    #[test]
    #[ignore] // FIXME: test currently disabled because it fails on IceCap
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
            TestEvent::write_program(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
            TestEvent::write_data(INTERSECTION_SET_SUM_CUSTOMER_DATA),
            TestEvent::write_data(INTERSECTION_SET_SUM_ADVERTISEMENT_DATA),
            TestEvent::execute(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
            TestEvent::read_result("/output/intersection-set-sum.dat"),
            TestEvent::ShutDown,
        ];

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
        .unwrap();
    }

    #[test]
    /// Integration test: string-edit-distance.
    /// Computing the string edit distance.
    fn integration_string_edit_distance() {
        let events = vec![
            TestEvent::write_program(STRING_EDIT_DISTANCE_WASM),
            TestEvent::write_data(STRING_1_DATA),
            TestEvent::write_data(STRING_2_DATA),
            TestEvent::execute(STRING_EDIT_DISTANCE_WASM),
            TestEvent::read_result("/output/string-edit-distance.dat"),
            TestEvent::ShutDown,
        ];

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
        .unwrap();
    }

    #[test]
    /// Integration test: private set intersection.
    /// Compute the intersection of two sets of persons.
    /// data sources: two vecs of persons, representing by Vec<Person>
    /// A standard two data sources scenario with attestation.
    fn integration_private_set_intersection() {
        let events = vec![
            TestEvent::write_program(PERSON_SET_INTERSECTION_WASM),
            TestEvent::write_data(PERSON_SET_1_DATA),
            TestEvent::write_data(PERSON_SET_2_DATA),
            TestEvent::execute(PERSON_SET_INTERSECTION_WASM),
            TestEvent::read_result("/output/private-set.dat"),
            TestEvent::ShutDown,
        ];

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
        .unwrap();
    }

    #[test]
    /// Attempt to fetch result without enough stream data.
    fn test_phase4_number_stream_accumulation_one_data_one_stream_with_attestation() {
        let events = vec![
            TestEvent::write_program(NUMBER_STREM_WASM),
            TestEvent::write_data(SINGLE_F64_DATA),
            TestEvent::read_result("/output/accumulation.dat"),
            TestEvent::ShutDown,
        ];

        let result = TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Integration test: deserialize postcard encoding and reserialize to json.
    fn integration_postcard_json() {
        let events = vec![
            TestEvent::write_program(POSTCARD_WASM),
            TestEvent::write_data(POSTCARD_DATA),
            TestEvent::execute(POSTCARD_WASM),
            TestEvent::read_result("/output/postcard_wasm.txt"),
            TestEvent::ShutDown,
        ];

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
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
            TestEvent::execute(LOGISTICS_REGRESSION_WASM),
            // only read two outputs
            TestEvent::read_result("/output/idash2017/generate-data-0.dat"),
            TestEvent::read_result("/output/idash2017/generate-data-1.dat"),
            TestEvent::ShutDown,
        ]);

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
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
            TestEvent::execute(MACD_WASM),
            // only read two outputs
            TestEvent::read_result("/output/macd/generate-1000.dat"),
            TestEvent::ShutDown,
        ]);

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
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
            TestEvent::execute(INTERSECTION_SET_SUM_WASM),
            // only read two outputs
            TestEvent::read_result("/output/private-set-inter-sum/data-2000-0"),
            TestEvent::ShutDown,
        ]);

        TestExecutor::test_template(
            POLICY,
            CLIENT_CERT,
            CLIENT_KEY,
            events,
            Duration::from_secs(TIME_OUT_SECS),
        )
        .unwrap();
    }

    /// Events that drive the test.
    #[derive(Debug, Clone)]
    enum TestEvent {
        // Check the policy and runtime hash
        CheckHash,
        // Write a remote file
        WriteFile(String, PathBuf),
        // Append a remote file
        AppendFile(String, PathBuf),
        // Execute a remote file
        Execute(String),
        // Read a remote file
        ReadFile(String),
        // Request to shutdown the runtime
        ShutDown,
    }

    impl TestEvent {
        /// Create a test event for provisioning program. The function adds the local and remote
        /// path prefices on the filename.
        fn write_program(filename: &str) -> TestEvent {
            TestEvent::WriteFile(runtime_program_dir(filename), program_dir(filename))
        }

        /// Create a test event for provisioning data. The function adds the local and remote
        /// path prefices on the filename.
        fn write_data(filename: &str) -> TestEvent {
            TestEvent::WriteFile(runtime_data_dir(filename), data_dir(filename))
        }

        /// Create a list of events for provisioning data files in the `local_dir_path`. The
        /// `local_dir_path` will be replaced by `remote_dir_path`.
        fn write_all<T: AsRef<Path>, K: AsRef<Path>>(
            dir_path: T,
            remote_dir_path: K,
        ) -> Vec<TestEvent> {
            TestEvent::input_list(dir_path, remote_dir_path)
                .into_iter()
                .map(|(remote, local)| TestEvent::WriteFile(remote, local))
                .collect()
        }

        /// Create a test event for executing a program. The function adds the remote
        /// path prefices on the filename.
        fn execute<T: AsRef<str>>(filename: T) -> TestEvent {
            TestEvent::Execute(runtime_program_dir(filename))
        }

        /// Create a test event for reading result.
        fn read_result<T: AsRef<str>>(filepath: T) -> TestEvent {
            TestEvent::ReadFile(String::from(filepath.as_ref()))
        }

        /// Function produces a vec of input lists. Each list corresponds to a round
        /// and is a vec of pairs of remote (des) file and local (src) file path,
        /// which corresponds to provisioning/appending the content of the local file to the remote file.
        fn batch_process_events<T: AsRef<Path>, K: AsRef<str>, Q: AsRef<str>>(
            local_dir_path: T,
            program_filename: K,
            result_path: Q,
        ) -> Vec<TestEvent> {
            // Load the remote input path, otherwise use default `/input/`
            let remote_dir_path = env::var("REMOTE_DATA_DIR").unwrap_or("/input/".to_string());

            // Construct the TestEvent gradually and append to this vec.
            let mut rst = Vec::new();

            // traverse the `local_dir_path`. Assume sub-directories are sorted,
            // e.g. `1` `2` `3` `4` `5`. Each sub-directory contains files provisioned to
            // the remote in each batch. Note that the provisioning use `append` request rather then
            // `write` request anf the remote path is of prefix `remote_dir_path`.
            // For example, in the previous example, if in the second batch, sub-directory `2`,
            // there is a file `local_dir_path/2/a.dat`,
            // then a TestEvent::Append('remote_dir_path/a.dat', `local_dir_path/2/a.dat`) will be
            // created.
            let mut dir_entries = local_dir_path
                .as_ref()
                .read_dir()
                .expect(&format!("invalid path: {:?}", local_dir_path.as_ref()))
                .filter_map(|e| e.map(|x| x.path()).ok())
                .collect::<Vec<_>>();
            dir_entries.sort();
            info!("dir_entries: {:?}", dir_entries);

            // borrow so the loop will not complain on the lifetime.
            let program_filename = program_filename.as_ref();
            let result_path = result_path.as_ref();

            // Add append, execute and read_result events in each round.
            for entry in dir_entries.iter() {
                // Add all the append requests.
                rst.append(
                    &mut TestEvent::input_list(entry, &remote_dir_path)
                        .into_iter()
                        .map(|(remote, local)| TestEvent::AppendFile(remote, local))
                        .collect(),
                );
                // Add execute request.
                rst.push(TestEvent::execute(program_filename));
                rst.push(TestEvent::read_result(result_path));
            }

            rst
        }

        /// Function produces a vec of pairs of remote (des) file and local (src) file path,
        /// which corresponds to provisioning/overwriting the content of the local file to the remote file.
        /// Read all files and diretory in the path of 'dir_path' in the local machine and replace the prefix with 'remote_dir_path'.
        /// E.g. if call the function with '/local/path/' and '/remote/path/',
        /// the result could be [(/remote/path/a.txt, /local/path/a.txt), (/remote/path/b/c.txt, /local/path/b/c.txt), ... ].
        fn input_list<T: AsRef<Path>, K: AsRef<Path>>(
            dir_path: T,
            remote_dir_path: K,
        ) -> Vec<(String, PathBuf)> {
            let mut rst = Vec::new();
            let dir_path = dir_path.as_ref();

            // Traverse all files and directories.
            for entry in dir_path
                .read_dir()
                .expect(&format!("invalid path: {:?}", dir_path))
            {
                let entry = entry.expect("invalid entry").path();
                let remote_entry_path = remote_dir_path.as_ref().join(
                    entry
                        .strip_prefix(dir_path)
                        .expect("Failed to strip entry prefix"),
                );

                if entry.is_dir() {
                    // If it a directory traverse recursively.
                    rst.append(&mut TestEvent::input_list(entry, remote_entry_path))
                } else if entry.is_file() {
                    let entry_path = entry.to_str().expect("Failed to parse the entry path");
                    rst.push((
                        remote_entry_path
                            .to_str()
                            .expect("Failed to parse remote entry path")
                            .to_string(),
                        PathBuf::from(entry_path),
                    ))
                }
            }

            rst
        }
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
        client_connection: rustls::ClientConnection,
        client_connection_id: u32,
        // A alive flag. This is to solve the problem where the server thread still in loop while
        // client thread is terminated.
        alive_flag: Arc<AtomicBool>,
        // Hold the server thread. The test will join the thread in the end to check the server
        // state.
        server_thread: JoinHandle<Result<(), String>>,
    }

    impl TestExecutor {
        /// This is the template. The template appends the path to the policy, and client
        /// certificate and key file, initials the test veracruz server and a mock client
        /// accordingly, and then executes the test-case driven by mock client `events`.
        fn test_template<P: AsRef<str>, Q: AsRef<str>, K: AsRef<str>>(
            policy_filename: P,
            client_cert_filename: Q,
            client_key_filename: K,
            events: Vec<TestEvent>,
            timeout: Duration,
        ) -> Result<(), Box<dyn Error + 'static>> {
            Self::new(
                policy_dir(policy_filename),
                cert_key_dir(client_cert_filename),
                cert_key_dir(client_key_filename),
            )?
            .execute(events, timeout)?;
            Ok(())
        }

        /// Create a new test executor. It initiates a server in a separate thread and creates a
        /// pair of channels between the main thread, who acts as a client, and the server thread.
        /// Those two channels simulate the network.
        fn new<P: AsRef<Path>, Q: AsRef<Path>, K: AsRef<Path>>(
            policy_path: P,
            client_cert_path: Q,
            client_key_path: K,
        ) -> Result<Self, Box<dyn Error + 'static>> {
            info!("Initialise test configuration and proxy attestation server.");
            // Read the the policy
            let (policy, policy_json, policy_hash) = read_policy(policy_path)?;

            // start the proxy attestation server
            proxy_attestation_setup(policy.proxy_attestation_server_url().clone());

            info!("Create simulated connection channels.");
            // Create two channel, simulating the connecting channels.
            let (server_tls_sender, client_tls_receiver) = channel::<Vec<u8>>();
            let (client_tls_sender, server_tls_receiver) = channel::<(u32, Vec<u8>)>();

            info!("Initialise a client with its certificate and key.");
            // Create a fake client session which only ends to the simulated connecting channel.
            let mut client_connection = create_client_test_connection(
                client_cert_path,
                client_key_path,
                &policy.ciphersuite(),
            )?;
            // Set the buffer size to unlimited. The `client_send` function assumes this property.
            client_connection.set_buffer_limit(None);

            info!("Initialise Veracruz runtime.");
            // Create the server
            let mut veracruz_server = VeracruzServerEnclave::new(&policy_json)?;

            // Create the client tls session. Note that we need the session id.
            let client_connection_id = veracruz_server.new_tls_session()?;
            if client_connection_id == 0 {
                return Err(String::from("client session id is zero").into());
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
                    &mut veracruz_server,
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
                client_tls_sender,
                client_tls_receiver,
                alive_flag,
                server_thread,
            })
        }

        /// This function simulating a Veracruz server, it should run on a separate thread.
        fn simulated_server(
            veracruz_server: &mut dyn veracruz_server::VeracruzServer,
            sender: Sender<Vec<u8>>,
            receiver: Receiver<(u32, Vec<u8>)>,
            test_alive_flag: Arc<AtomicBool>,
            test_init_flag: Arc<AtomicBool>,
        ) -> Result<(), String> {
            info!("Server: simulated server loop starts...");

            test_init_flag.store(true, Ordering::SeqCst);

            while test_alive_flag.load(Ordering::SeqCst) {
                let received = receiver.recv();
                let (session_id, received_buffer) =
                    received.map_err(|e| format!("Server: {:?}", e))?;
                info!(
                    "Server: receive {} byte(s) on session ID {}.",
                    received_buffer.len(),
                    session_id
                );

                let (veracruz_active_flag, output_data_option) = veracruz_server
                    .tls_data(session_id, received_buffer)
                    .map_err(|e| {
                        // This point has a high chance to fail.
                        error!("Veracruz Server: {:?}", e);
                        format!("Failed to send TLS data.  Error produced: {:?}.", e)
                    })?;

                // At least send an empty message, this notifies the client.
                let output_data = output_data_option.unwrap_or_else(|| vec![vec![]]);

                for output in output_data.iter() {
                    sender.send(output.clone()).map_err(|e| {
                        format!(
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
            Err(format!(
                "VeracruzServer TLS loop dieing due to no activity..."
            ))
        }

        /// Execute this test. The client sends messages though the channel to the server
        /// thread driven by `events`. It comsumes the ownership of `self`,
        /// because it will join server thread at the end.
        fn execute(
            mut self,
            events: Vec<TestEvent>,
            timeout: Duration,
        ) -> Result<(), Box<dyn Error + 'static>> {
            // Spawn a thread that will send the timeout signal by killing alive flag.
            let alive_flag_clone = self.alive_flag.clone();
            std::thread::spawn(move || {
                std::thread::sleep(timeout);
                if alive_flag_clone.load(Ordering::SeqCst) {
                    error!("--->>> Force timeout. It is very likely to trigger error on the test. <<<---");
                }
                alive_flag_clone.store(false, Ordering::SeqCst);
            });

            // process test events
            for event in events.iter() {
                info!("Process event {:?}.", event);
                let time_init = Instant::now();
                let response = self.process_event(&event).map_err(|e| {
                    error!("Client: {:?}", e);
                    self.alive_flag.store(false, Ordering::SeqCst);
                    e
                })?;
                info!(
                    "The event {:?} finished with response status {:?} in {:?}.",
                    event,
                    response.get_status(),
                    time_init.elapsed()
                );
            }

            // Wait the server to finish.
            self.server_thread
                .join()
                .map_err(|e| format!("server thread failed with error {:?}", e))??;
            Ok(())
        }

        fn process_event(
            &mut self,
            event: &TestEvent,
        ) -> Result<transport_protocol::RuntimeManagerResponse, Box<dyn Error + 'static>> {
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
                TestEvent::ReadFile(remote_path) => self.read_file(&remote_path)?,
                TestEvent::ShutDown => self.shutdown()?,
            };
            Ok(transport_protocol::parse_runtime_manager_response(
                None, &response,
            )?)
        }

        fn check_policy_hash(&mut self) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
            let serialized_request_policy_hash =
                transport_protocol::serialize_request_policy_hash().map_err(|e| {
                    format!(
                        "Failed to serialize request for policy hash.  Error produced: {:?}.",
                        e
                    )
                })?;

            let response = self.client_send(&serialized_request_policy_hash[..])?;
            let parsed_response =
                transport_protocol::parse_runtime_manager_response(None, &response)?;
            let status = parsed_response.get_status();

            if status != transport_protocol::ResponseStatus::SUCCESS {
                return Err(format!("Received non-Success status: {:?}.", status).into());
            }
            let received_hash = std::str::from_utf8(&parsed_response.get_policy_hash().data)?;
            info!("Received {:?} as hash.", received_hash);
            if received_hash != self.policy_hash {
                return Err(format!(
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
        fn check_runtime_manager_hash(&mut self) -> Result<(), Box<dyn Error + 'static>> {
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
            let certs = self.client_connection.peer_certificates().ok_or(format!(
                "No peer certificate found. Potentially wait handshake."
            ))?;

            let ee_cert = webpki::EndEntityCert::try_from(certs[0].as_ref())?;
            let ues = ee_cert.unrecognized_extensions();

            // check for OUR extension
            let encoded_extension_id: [u8; 3] = [
                VERACRUZ_RUNTIME_HASH_EXTENSION_ID[0] * 40 + VERACRUZ_RUNTIME_HASH_EXTENSION_ID[1],
                VERACRUZ_RUNTIME_HASH_EXTENSION_ID[2],
                VERACRUZ_RUNTIME_HASH_EXTENSION_ID[3],
            ];
            let data = ues
                .get(&encoded_extension_id[..])
                .ok_or(format!("Our certificate extension is not present."))?;
            info!("Certificate extension found.");

            let extension_data = data
                .read_all(format!("Can't read veracruz custom extension."), |input| {
                    Ok(input.read_bytes_to_end())
                })?;

            if compare_policy_hash(
                extension_data.as_slice_less_safe(),
                &self.policy,
                &target_platform,
            ) {
                Ok(())
            } else {
                Err(format!("None of the runtime manager hashes matched.").into())
            }
        }

        #[inline]
        fn write_file<P: AsRef<Path>>(
            &mut self,
            remote_path: &str,
            local_path: P,
        ) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
            // Read the local data and create a protobuf message.
            let data = {
                let mut data_file = File::open(local_path)?;
                let mut data_buffer = Vec::new();
                data_file.read_to_end(&mut data_buffer)?;
                data_buffer
            };
            let serialized_data = transport_protocol::serialize_write_file(&data, remote_path)?;
            self.client_send(&serialized_data[..])
        }

        #[inline]
        fn append_file<P: AsRef<Path>>(
            &mut self,
            remote_path: &str,
            local_path: P,
        ) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
            // Read the local data and create a protobuf message.
            let data = {
                let mut data_file = File::open(local_path)?;
                let mut data_buffer = Vec::new();
                data_file.read_to_end(&mut data_buffer)?;
                data_buffer
            };
            let serialized_data = transport_protocol::serialize_stream(&data, remote_path)?;
            self.client_send(&serialized_data[..])
        }

        #[inline]
        fn execute_program(
            &mut self,
            remote_path: &str,
        ) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
            self.client_send(&transport_protocol::serialize_request_result(remote_path)?[..])
        }

        #[inline]
        fn read_file(&mut self, remote_path: &str) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
            self.client_send(&transport_protocol::serialize_read_file(remote_path)?[..])
        }

        #[inline]
        fn shutdown(&mut self) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
            self.client_send(&transport_protocol::serialize_request_shutdown()?[..])
        }

        /// The client sends TLS packages via the simulated channel.
        fn client_send(&mut self, send_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
            info!(
                "Client: client send with length of data {:?}",
                send_data.len()
            );
            let connection: &mut rustls::ClientConnection = &mut self.client_connection;
            let mut connection_writter = connection.writer();
            // The buffer size is set unlimited. `write_all` here should not fail.
            connection_writter
                .write_all(&send_data[..])
                .map_err(|e| format!("Failed to send all data.  Error produced: {:?}.", e))?;
            connection_writter.flush()?;

            let mut output: Vec<u8> = Vec::new();

            connection
                .write_tls(&mut output)
                .map_err(|e| format!("Failed to write TLS.  Error produced: {:?}.", e))?;

            self.client_tls_sender
                .send((self.client_connection_id, output))
                .map_err(|e| {
                    format!(
                        "Failed to send data on TX channel.  Error produced: {:?}.",
                        e
                    )
                })?;

            info!("Client: package is sent");

            // Always check if other threads in the this test instance is still running.
            while self.alive_flag.load(Ordering::SeqCst) {
                // Priority write.
                if connection.wants_write() {
                    info!("Client: session wants write...");
                    let mut output: Vec<u8> = Vec::new();
                    connection
                        .write_tls(&mut output)
                        .map_err(|e| format!("Failed to write TLS. Error produced: {:?}.", e))?;
                    let _res = self
                        .client_tls_sender
                        .send((self.client_connection_id, output))
                        .map_err(|e| {
                            format!(
                                "Failed to send data on TX channel. Error produced: {:?}.",
                                e
                            )
                        })?;
                } else if !connection.is_handshaking() || connection.wants_read() {
                    let received = self.client_tls_receiver.recv()?;
                    info!("Client: received is OK, and we're not handshaking...");

                    // It is possible to receive an empty messsage.
                    if received.len() == 0 {
                        continue;
                    }

                    // convert the vec<u8> to read trait
                    let mut slice = &received[..];
                    connection
                        .read_tls(&mut slice)
                        .map_err(|e| format!("Failed to read TLS. Error produced: {:?}.", e))?;
                    connection.process_new_packets().map_err(|e| {
                        format!("Failed to process new packets. Error produced: {:?}.", e)
                    })?;

                    let mut received_buffer: Vec<u8> = Vec::new();

                    match connection.reader().read_to_end(&mut received_buffer) {
                        Ok(_num) => (),
                        // It is allowed to block, but we care more on the received buffer.
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(err) => {
                            return Err(format!(
                                "Failed to read data to end.  Error produced: {:?}.",
                                err
                            )
                            .into());
                        }
                    };

                    info!("Client: received_buffer.len() {}", received_buffer.len());

                    if received_buffer.len() > 0 {
                        info!("Client: finished sending via TLS.");
                        // NOTE: this is the place where function succeeds.
                        return Ok(received_buffer);
                    }
                }
            }

            // If reach here, it means the server crashed.
            Err(format!("Terminate due to server crash").into())
        }
    }

    /// Auxiliary function: read policy file
    fn read_policy<T: AsRef<Path>>(
        fname: T,
    ) -> Result<(Policy, String, String), Box<dyn Error + 'static>> {
        let fname = fname.as_ref();
        let policy_json = std::fs::read_to_string(fname)?;

        let policy_hash = sha256(policy_json.as_bytes());
        let policy_hash_str = hex::encode(&policy_hash);
        let policy = Policy::from_json(policy_json.as_ref())?;
        Ok((policy, policy_json.to_string(), policy_hash_str))
    }

    /// Auxiliary function: initialise the Veracruz server from policy and open a tls session
    fn init_veracruz_server_and_tls_session<T: AsRef<str>>(
        policy_json: T,
    ) -> Result<(VeracruzServerEnclave, u32), Box<dyn Error + 'static>> {
        let mut veracruz_server = VeracruzServerEnclave::new(policy_json.as_ref())?;

        // wait for the client to start
        std::thread::sleep(Duration::from_millis(100));

        let session_id = veracruz_server.new_tls_session()?;
        if session_id != 0 {
            Ok((veracruz_server, session_id))
        } else {
            Err(format!("Session ID cannot be zero").into())
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
    ) -> Result<rustls::ClientConnection, Box<dyn Error + 'static>> {
        let client_cert = read_cert_file(client_cert_filename)?;

        let client_priv_key = read_priv_key_file(client_key_filename)?;

        let proxy_service_cert = {
            let data = std::fs::read(cert_key_dir(CA_CERT))?;
            let certs = rustls_pemfile::certs(&mut data.as_slice())?;
            certs[0].clone()
        };

        let cipher_suite =
            veracruz_utils::lookup_ciphersuite(ciphersuite_str).ok_or_else(|| {
                VeracruzServerError::InvalidCiphersuiteError(ciphersuite_str.to_string())
            })?;
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(&rustls::Certificate(proxy_service_cert))?;

        let client_config = rustls::ClientConfig::builder()
            .with_cipher_suites(&[cipher_suite])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS12])?
            .with_root_certificates(root_store)
            .with_single_cert([client_cert].to_vec(), client_priv_key)?;

        let enclave_name_as_server = rustls::ServerName::try_from("ComputeEnclave.dev")?;
        Ok(rustls::ClientConnection::new(
            Arc::new(client_config),
            enclave_name_as_server,
        )?)
    }

    fn read_cert_file<P: AsRef<Path>>(
        filename: P,
    ) -> Result<rustls::Certificate, Box<dyn Error + 'static>> {
        let mut cert_file = File::open(filename)?;
        let mut cert_buffer = Vec::new();
        cert_file.read_to_end(&mut cert_buffer)?;
        let mut cursor = std::io::Cursor::new(cert_buffer);
        let certs = rustls_pemfile::certs(&mut cursor)?;
        if certs.len() == 0 {
            Err(format!("certs.len() is zero").into())
        } else {
            Ok(rustls::Certificate(certs[0].clone()))
        }
    }

    fn read_priv_key_file<P: AsRef<Path>>(
        filename: P,
    ) -> Result<rustls::PrivateKey, Box<dyn Error + 'static>> {
        let mut key_file = File::open(filename)?;
        let mut key_buffer = Vec::new();
        key_file.read_to_end(&mut key_buffer)?;
        let mut cursor = std::io::Cursor::new(key_buffer);
        let rsa_keys = rustls_pemfile::rsa_private_keys(&mut cursor)?;
        Ok(rustls::PrivateKey(rsa_keys[0].clone()))
    }
}
