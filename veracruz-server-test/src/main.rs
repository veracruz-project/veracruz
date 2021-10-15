//! Veracruz-server-specific tests
//!
//! One of the main integration tests for Veracruz, as a lot of material is
//! imported directly or indirectly via these tests.
//!
//! ## Authors
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
    use env_logger;
    use lazy_static::lazy_static;
    use log::{debug, error, info, Level};
    use rand;
    use rand::Rng;
    use ring;

    use serde::Deserialize;
    use transport_protocol;
    use veracruz_server::veracruz_server::*;
    #[cfg(feature = "nitro")]
    use veracruz_server::VeracruzServerNitro as VeracruzServerEnclave;
    #[cfg(feature = "sgx")]
    use veracruz_server::VeracruzServerSGX as VeracruzServerEnclave;
    #[cfg(feature = "tz")]
    use veracruz_server::VeracruzServerTZ as VeracruzServerEnclave;
    #[cfg(feature = "icecap")]
    use veracruz_server::VeracruzServerIceCap as VeracruzServerEnclave;
    use veracruz_utils::{platform::Platform, policy::policy::Policy, VERACRUZ_RUNTIME_HASH_EXTENSION_ID};
    use proxy_attestation_server;
    use std::{
        collections::{HashMap, HashSet},
        env,
        io::{Read, Write},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicU32, Ordering},
            Mutex, Once,
        },
        thread,
        time::Instant,
        vec::Vec,
    };

    // Policy files
    const ONE_DATA_SOURCE_POLICY: &'static str = "one_data_source_policy.json";
    const GET_RANDOM_POLICY: &'static str = "get_random_policy.json";
    const LINEAR_REGRESSION_POLICY: &'static str = "one_data_source_policy.json";
    const TWO_DATA_SOURCE_STRING_EDIT_DISTANCE_POLICY: &'static str =
        "two_data_source_string_edit_distance_policy.json";
    const TWO_DATA_SOURCE_INTERSECTION_SET_POLICY: &'static str =
        "two_data_source_intersection_set_policy.json";
    const TWO_DATA_SOURCE_PRIVATE_SET_INTERSECTION_POLICY: &'static str =
        "two_data_source_private_set_intersection_policy.json";
    const MULTIPLE_KEY_POLICY: &'static str = "test_multiple_key_policy.json";
    const IDASH2017_POLICY: &'static str =
        "idash2017_logistic_regression_policy.json";
    const MACD_POLICY: &'static str =
        "moving_average_convergence_divergence.json";
    const PRIVATE_SET_INTER_SUM_POLICY: &'static str =
        "private_set_intersection_sum.json";
    const NUMBER_STREAM_ACCUMULATION_POLICY: &'static str =
        "number-stream-accumulation.json";
    const BASIC_FILE_READ_WRITE_POLICY: &'static str =
        "basic_file_read_write.json";
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
    const CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM: &'static str =
        "intersection-set-sum.wasm";
    const PERSON_SET_INTERSECTION_WASM: &'static str =
        "private-set-intersection.wasm";
    const LOGISTICS_REGRESSION_WASM: &'static str =
        "idash2017-logistic-regression.wasm";
    const MACD_WASM: &'static str = "moving-average-convergence-divergence.wasm";
    const INTERSECTION_SET_SUM_WASM: &'static str =
        "private-set-intersection-sum.wasm";
    const NUMBER_STREM_WASM: &'static str = "number-stream-accumulation.wasm";
    // Data
    const LINEAR_REGRESSION_DATA: &'static str = "linear-regression.dat";
    const INTERSECTION_SET_SUM_CUSTOMER_DATA: &'static str =
        "intersection-customer.dat";
    const INTERSECTION_SET_SUM_ADVERTISEMENT_DATA: &'static str =
        "intersection-advertisement-viewer.dat";
    const STRING_1_DATA: &'static str = "hello-world-1.dat";
    const STRING_2_DATA: &'static str = "hello-world-2.dat";
    const PERSON_SET_1_DATA: &'static str = "private-set-1.dat";
    const PERSON_SET_2_DATA: &'static str = "private-set-2.dat";
    const SINGLE_F64_DATA: &'static str = "number-stream-init.dat";
    const VEC_F64_1_DATA: &'static str = "number-stream-1.dat";
    const VEC_F64_2_DATA: &'static str = "number-stream-2.dat";
    const LOGISTICS_REGRESSION_DATA_PATH: &'static str = "idash2017/";
    const MACD_DATA_PATH: &'static str = "macd/";

    static SETUP: Once = Once::new();
    static DEBUG_SETUP: Once = Once::new();
    lazy_static! {
        // This is a semi-hack to test of if the debug is called in the SGX env.
        // In each run this flag should be set false.
        static ref DEBUG_IS_CALLED: AtomicBool = AtomicBool::new(false);
        // A global flag, between the server thread and the client thread in the test_template.
        // If one of the two threads hits an Error, it sets the flag to `false` and
        // thus stops another thread. Without this hack, a failure can cause non-termination.
        static ref CONTINUE_FLAG_HASH: Mutex<HashMap<u32,bool>> = Mutex::new(HashMap::<u32,bool>::new());
        static ref NEXT_TICKET: AtomicU32 = AtomicU32::new(0);
    }

    pub fn policy_path(filename: &str) -> PathBuf {
        PathBuf::from(env::var("VERACRUZ_POLICY_DIR").unwrap_or("../test-collateral".to_string()))
            .join(filename)
    }
    pub fn trust_path(filename: &str) -> PathBuf {
        PathBuf::from(env::var("VERACRUZ_TRUST_DIR").unwrap_or("../test-collateral".to_string()))
            .join(filename)
    }
    pub fn program_path(filename: &str) -> PathBuf {
        PathBuf::from(env::var("VERACRUZ_PROGRAM_DIR").unwrap_or("../test-collateral".to_string()))
            .join(filename)
    }
    pub fn data_dir(filename: &str) -> PathBuf {
        PathBuf::from(env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()))
            .join(filename)
    }

    pub fn setup(proxy_attestation_server_url: String) -> u32 {
        #[allow(unused_assignments)]
        let rst = NEXT_TICKET.fetch_add(1, Ordering::SeqCst);

        SETUP.call_once(|| {
            println!("SETUP.call_once called");
            let _main_loop_handle = std::thread::spawn(|| {
                let mut sys = System::new("Veracruz Proxy Attestation Server");
                println!("spawned thread calling server with url:{:?}", proxy_attestation_server_url);
                #[cfg(feature = "debug")]
                let server =
                    proxy_attestation_server::server::server(
                        proxy_attestation_server_url,
                        trust_path(CA_CERT).as_path(),
                        trust_path(CA_KEY).as_path(),
                        true)
                        .unwrap();
                #[cfg(not(feature = "debug"))]
                let server =
                    proxy_attestation_server::server::server(
                        proxy_attestation_server_url,
                        trust_path(CA_CERT).as_path(),
                        trust_path(CA_KEY).as_path(),
                        false)
                        .unwrap();
                sys.block_on(server).unwrap();
            });
        });
        // sleep to wait for the proxy attestation server to start
        std::thread::sleep(std::time::Duration::from_millis(100));
        rst
    }

    pub fn debug_setup() {
        DEBUG_SETUP.call_once(|| {
            std::env::set_var("RUST_LOG", "debug,actix_server=debug,actix_web=debug");
            env_logger::builder()
                // Check if the debug is called.
                .format(|buf, record| {
                    let message = format!("{}", record.args());
                    if record.level() == Level::Debug
                        && message.contains("Enclave debug message")
                    {
                        DEBUG_IS_CALLED.store(true, Ordering::SeqCst);
                    }
                    writeln!(buf, "[{} {}]: {}", record.target(), record.level(), message)
                })
                .init();
        });
    }

    #[test]
    /// Load every valid policy file in the test-collateral/ and in
    /// test-collateral/invalid_policy,
    /// initialise an enclave.
    fn test_phase1_init_destroy_enclave() {
        // all the json in test-collateral should be valid policy
        let policy_dir = PathBuf::from(env::var("VERACRUZ_POLICY_DIR").
            unwrap_or("../test-collateral".to_string()).clone());
        iterate_over_policy(policy_dir.as_path(), |policy_json| {
            let policy = Policy::from_json(&policy_json);
            assert!(policy.is_ok());
            if let Ok(policy) = policy {
                setup(policy.proxy_attestation_server_url().clone());
                let result = VeracruzServerEnclave::new(&policy_json);
                assert!(result.is_ok(), "error:{:?}", result.err());
            }
        });

        // If any json in test-collateral/invalid_policy is valid in Policy::new(),
        // it must also valid in term of VeracruzServerEnclave::new()
        iterate_over_policy(policy_path("invalid_policy").as_path(), |policy_json| {
            let policy = Policy::from_json(&policy_json);
            if let Ok(policy) = policy {
                setup(policy.proxy_attestation_server_url().clone());
                let result = VeracruzServerEnclave::new(&policy_json);
                assert!(
                    result.is_ok(),
                    "error:{:?}, json:{:?}",
                    result.err(),
                    policy_json
                );
            }
        });
    }

    #[test]
    /// Load policy file and check if a new session tls can be opened
    fn test_phase1_new_session() {
        let policy_dir = PathBuf::from(env::var("VERACRUZ_POLICY_DIR").
            unwrap_or("../test-collateral".to_string()).clone());
        iterate_over_policy(policy_dir.as_path(), |policy_json| {
            let policy = Policy::from_json(&policy_json).unwrap();
            // start the proxy attestation server
            setup(policy.proxy_attestation_server_url().clone());
            let result = init_veracruz_server_and_tls_session(policy_json);
            assert!(result.is_ok(), "error:{:?}", result.err());
        });
    }

    #[test]
    /// Load the Veracruz server and generate the self-signed certificate
    fn test_phase1_enclave_self_signed_cert() {
        // start the proxy attestation server
        let policy_dir = PathBuf::from(env::var("VERACRUZ_POLICY_DIR").
            unwrap_or("../test-collateral".to_string()).clone());
        iterate_over_policy(policy_dir.as_path(), |policy_json| {
            let policy = Policy::from_json(&policy_json).unwrap();
            setup(policy.proxy_attestation_server_url().clone());
            let result = VeracruzServerEnclave::new(&policy_json);
            assert!(result.is_ok());
        });
    }

    #[test]
    /// Test the attestation flow without sending any program or data into the Veracruz server
    fn test_phase1_attestation_only() {
        let (policy, policy_json, _) = read_policy(policy_path(ONE_DATA_SOURCE_POLICY).as_path()).unwrap();
        setup(policy.proxy_attestation_server_url().clone());

        let ret = VeracruzServerEnclave::new(&policy_json);

        let _veracruz_server = ret.unwrap();
    }

    #[test]
    #[ignore]
    /// Test if the detect for calling `debug!` in enclave works.
    fn test_debug1_fire_test_on_debug() {
        debug_setup();
        DEBUG_IS_CALLED.store(false, Ordering::SeqCst);
        debug!("Enclave debug message stud");
        assert!(DEBUG_IS_CALLED.load(Ordering::SeqCst));
    }

    #[test]
    #[ignore]
    /// Test if the detect for calling `debug!` in enclave works.
    fn test_debug2_linear_regression_without_debug() {
        debug_setup();
        DEBUG_IS_CALLED.store(false, Ordering::SeqCst);
        test_phase2_linear_regression_single_data_no_attestation();
        assert!(!DEBUG_IS_CALLED.load(Ordering::SeqCst));
    }

    #[test]
    /// Attempt to establish a client session with the Veracruz server with an invalid client certificate
    fn test_phase2_single_session_with_invalid_client_certificate() {
        let (policy, policy_json, _) = read_policy(policy_path(ONE_DATA_SOURCE_POLICY).as_path()).unwrap();
        // start the proxy attestation server
        setup(policy.proxy_attestation_server_url().clone());
        let (veracruz_server, _) = init_veracruz_server_and_tls_session(&policy_json).unwrap();

        let client_cert_filename = trust_path("never_used_cert.pem");
        let client_key_filename = trust_path("client_rsa_key.pem");

        let mut _client_session = create_client_test_session(
            client_cert_filename.as_path(),
            client_key_filename.as_path(),
        );
    }

    #[test]
    /// Integration test:
    /// computation: echoing
    /// data sources: a single input under filename `input.txt`.
    fn test_phase2_basic_file_read_write_no_attestation() {
        let result = test_template::<Vec<u8>>(
            policy_path(BASIC_FILE_READ_WRITE_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(READ_FILE_WASM).to_string_lossy().into_owned().as_str()),
            &[("input.txt", data_dir(STRING_1_DATA).to_string_lossy().into_owned().as_str())],
            &[],
        );
        assert!(result.is_ok(), "error:{:?}", result);
    }

    #[cfg(not(feature = "icecap"))]
    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: random-source, returning a vec of random u8
    /// data sources: none
    fn test_phase2_random_source_no_data_no_attestation() {
        let result = test_template::<Vec<u8>>(
            policy_path(GET_RANDOM_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(RANDOM_SOURCE_WASM).to_string_lossy().into_owned().as_str()),
            &[],
            &[],
        );
        assert!(result.is_ok(), "error:{:?}", result);
    }

    #[test]
    /// Attempt to fetch the result without program nor data
    fn test_phase2_random_source_no_program_no_data() {
        let result = test_template::<Vec<u8>>(
            policy_path(GET_RANDOM_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            None,
            &[],
            &[],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Attempt to provision a wrong program
    fn test_phase2_incorrect_program_no_attestation() {
        let result = test_template::<Vec<u8>>(
            policy_path(GET_RANDOM_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(STRING_EDIT_DISTANCE_WASM).to_string_lossy().into_owned().as_str()),
            &[],
            &[],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[cfg(not(feature = "icecap"))]
    #[test]
    /// Attempt to use an unauthorized key
    fn test_phase2_random_source_no_data_no_attestation_unauthorized_key() {
        let result = test_template::<Vec<u8>>(
            policy_path(GET_RANDOM_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(UNAUTHORIZED_KEY).as_path(),
            Some(program_path(RANDOM_SOURCE_WASM).to_string_lossy().into_owned().as_str()),
            &[],
            &[],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[cfg(not(feature = "icecap"))]
    #[test]
    /// Attempt to use an unauthorized certificate
    fn test_phase2_random_source_no_data_no_attestation_unauthorized_certificate() {
        let result = test_template::<Vec<u8>>(
            policy_path(GET_RANDOM_POLICY).as_path(),
            trust_path(UNAUTHORIZED_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(RANDOM_SOURCE_WASM).to_string_lossy().into_owned().as_str()),
            &[],
            &[],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[cfg(not(feature = "icecap"))]
    #[test]
    /// A unauthorized client attempt to connect the service
    fn test_phase2_random_source_no_data_no_attestation_unauthorized_client() {
        let result = test_template::<Vec<u8>>(
            policy_path(GET_RANDOM_POLICY).as_path(),
            trust_path(UNAUTHORIZED_CERT).as_path(),
            trust_path(UNAUTHORIZED_KEY).as_path(),
            Some(program_path(RANDOM_SOURCE_WASM).to_string_lossy().into_owned().as_str()),
            &[],
            &[],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[cfg(not(feature = "icecap"))]
    #[test]
    /// Attempt to provision more data than expected
    fn test_phase2_random_source_one_data_no_attestation() {
        let result = test_template::<Vec<u8>>(
            policy_path(GET_RANDOM_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(RANDOM_SOURCE_WASM).to_string_lossy().into_owned().as_str()),
            &[("input-0", data_dir(LINEAR_REGRESSION_DATA).to_string_lossy().into_owned().as_str())],
            &[],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[derive(Debug, Deserialize)]
    struct LinearRegression {
        /// Gradient of the linear relationship.
        gradient: f64,
        /// Y-intercept of the linear relationship.
        intercept: f64,
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: linear regression, computing the grandient and intercept, ie the LinearRegression struct,
    /// given a series of point in the two-dimension space.
    /// data sources: linear-regression, a vec of points in two-dimention space, representing by
    /// Vec<(f64, f64)>
    fn test_phase2_linear_regression_single_data_no_attestation() {
        let result = test_template::<LinearRegression>(
            policy_path(LINEAR_REGRESSION_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(LINEAR_REGRESSION_WASM).to_string_lossy().into_owned().as_str()),
            &[("input-0", data_dir(LINEAR_REGRESSION_DATA).to_string_lossy().into_owned().as_str())],
            &[],
        );
        assert!(result.is_ok(), "error:{:?}", result);
    }

    #[test]
    /// Attempt to fetch result without data
    fn test_phase2_linear_regression_no_data_no_attestation() {
        let result = test_template::<LinearRegression>(
            policy_path(LINEAR_REGRESSION_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(LINEAR_REGRESSION_WASM).to_string_lossy().into_owned().as_str()),
            &[],
            &[],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: intersection sum, intersection of two data sources
    /// and then the sum of the values in the intersection.
    /// data sources: customer and advertisement, vecs of AdvertisementViewer and Customer
    /// respectively.
    /// ```no run
    /// struct AdvertisementViewer { id: String }
    /// struct Customer { id: String, total_spend: f64, }
    /// ```
    /// A standard two data source scenario, where the data provisioned in the
    /// reversed order (data 1, then data 0)
    fn test_phase2_intersection_sum_reversed_data_provisioning_two_data_no_attestation() {
        let result = test_template::<f64>(
            policy_path(TWO_DATA_SOURCE_INTERSECTION_SET_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM).to_string_lossy().into_owned().as_str()),
            &[
                // message sends out in the reversed order
                ("input-1", data_dir(INTERSECTION_SET_SUM_CUSTOMER_DATA).to_string_lossy().into_owned().as_str()),
                ("input-0", data_dir(INTERSECTION_SET_SUM_ADVERTISEMENT_DATA).to_string_lossy().into_owned().as_str()),
            ],
            &[],
        );
        assert!(result.is_ok(), "error:{:?}", result);
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: string-edit-distance, computing the string edit distance.
    /// data sources: two strings
    fn test_phase2_string_edit_distance_two_data_no_attestation() {
        let result = test_template::<usize>(
            policy_path(TWO_DATA_SOURCE_STRING_EDIT_DISTANCE_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(STRING_EDIT_DISTANCE_WASM).to_string_lossy().into_owned().as_str()),
            &[("input-0", data_dir(STRING_1_DATA).to_string_lossy().into_owned().as_str()),
                          ("input-1", data_dir(STRING_2_DATA).to_string_lossy().into_owned().as_str())],
            &[],
        );
        assert!(result.is_ok(), "error:{:?}", result);
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: linear regression, computing the grandient and intercept, ie the LinearRegression struct,
    /// given a series of point in the two-dimension space.
    /// data sources: linear-regression, a vec of points in two-dimention space, representing by
    /// Vec<(f64, f64)>
    /// A standard one data source scenario with attestation.
    fn test_phase3_linear_regression_one_data_with_attestation() {
        let result = test_template::<LinearRegression>(
            policy_path(ONE_DATA_SOURCE_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(LINEAR_REGRESSION_WASM).to_string_lossy().into_owned().as_str()),
            &[("input-0", data_dir(LINEAR_REGRESSION_DATA).to_string_lossy().into_owned().as_str())],
            &[],
        );
        assert!(result.is_ok(), "error:{:?}", result);
    }

    #[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
    struct Person {
        /// Name of the employee
        name: String,
        /// Internal ID of the employee
        employee_id: String,
        /// Age of the employee
        age: u8,
        /// Grade of the employee
        grade: u8,
    }

    #[cfg(not(feature = "icecap"))]
    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// compuatation: set intersection, computing the intersection of two sets of persons.
    /// data sources: two vecs of persons, representing by Vec<Person>
    /// A standard two data sources scenario with attestation.
    fn test_phase3_private_set_intersection_two_data_with_attestation() {
        let result = test_template::<HashSet<Person>>(
            policy_path(TWO_DATA_SOURCE_PRIVATE_SET_INTERSECTION_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(PERSON_SET_INTERSECTION_WASM).to_string_lossy().into_owned().as_str()),
            &[
                ("input-0", data_dir(PERSON_SET_1_DATA).to_string_lossy().into_owned().as_str()),
                ("input-1", data_dir(PERSON_SET_2_DATA).to_string_lossy().into_owned().as_str()),
            ],
            &[],
        );
        assert!(result.is_ok(), "error:{:?}", result);
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider, StreamProvider and ResultReader is the same party
    /// compuatation: sum of an initial f64 number and two streams of f64 numbers.
    /// data sources: an initial f64 value, and two vecs of f64, representing two streams.
    /// A standard one data source and two stream sources scenario with attestation.
    fn test_phase4_number_stream_accumulation_one_data_two_stream_with_attestation() {
        let result = test_template::<(u64, f64)>(
            policy_path(NUMBER_STREAM_ACCUMULATION_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(NUMBER_STREM_WASM).to_string_lossy().into_owned().as_str()),
            &[("input-0", data_dir(SINGLE_F64_DATA).to_string_lossy().into_owned().as_str())],
            &[("stream-0", data_dir(VEC_F64_1_DATA).to_string_lossy().into_owned().as_str()),
                            ("stream-1", data_dir(VEC_F64_2_DATA).to_string_lossy().into_owned().as_str())],
        );
        assert!(result.is_ok(), "error:{:?}", result);
    }

    #[test]
    /// Attempt to fetch result without enough stream data.
    fn test_phase4_number_stream_accumulation_one_data_one_stream_with_attestation() {
        let result = test_template::<f64>(
            policy_path(NUMBER_STREAM_ACCUMULATION_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(NUMBER_STREM_WASM).to_string_lossy().into_owned().as_str()),
            &[("input-0", data_dir(SINGLE_F64_DATA).to_string_lossy().into_owned().as_str())],
            &[("stream-0", data_dir(VEC_F64_1_DATA).to_string_lossy().into_owned().as_str())],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Attempt to provision stream data in the state of loading static data.
    fn test_phase4_number_stream_accumulation_no_data_two_stream_with_attestation() {
        let result = test_template::<f64>(
            policy_path(NUMBER_STREAM_ACCUMULATION_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(NUMBER_STREM_WASM).to_string_lossy().into_owned().as_str()),
            &[],
            &[("stream-0", data_dir(VEC_F64_1_DATA).to_string_lossy().into_owned().as_str()),
                            ("stream-1", data_dir(VEC_F64_2_DATA).to_string_lossy().into_owned().as_str())],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Attempt to provision more stream data.
    fn test_phase4_number_stream_accumulation_no_data_three_stream_with_attestation() {
        let result = test_template::<f64>(
            policy_path(NUMBER_STREAM_ACCUMULATION_POLICY).as_path(),
            trust_path(CLIENT_CERT).as_path(),
            trust_path(CLIENT_KEY).as_path(),
            Some(program_path(NUMBER_STREM_WASM).to_string_lossy().into_owned().as_str()),
            &[],
            &[
                ("stream-0", data_dir(VEC_F64_1_DATA).to_string_lossy().into_owned().as_str()),
                ("stream-1", data_dir(VEC_F64_2_DATA).to_string_lossy().into_owned().as_str()),
                ("stream-2", data_dir(VEC_F64_1_DATA).to_string_lossy().into_owned().as_str()),
            ],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Performance test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: logistic regression, https://github.com/kimandrik/IDASH2017.
    /// data sources: idash2017/*.dat
    fn test_performance_idash2017_with_attestation() {
        iterate_over_data(data_dir(LOGISTICS_REGRESSION_DATA_PATH).as_path(), |data_path| {
            info!("Data path: {}", data_path.to_string_lossy());
            let result = test_template::<(Vec<f64>, f64, f64)>(
                policy_path(IDASH2017_POLICY).as_path(),
                trust_path(CLIENT_CERT).as_path(),
                trust_path(CLIENT_KEY).as_path(),
                Some(program_path(LOGISTICS_REGRESSION_WASM).to_string_lossy().into_owned().as_str()),
                &[("input-0", data_path.to_string_lossy().into_owned().as_str())],
                &[],
            );
            assert!(result.is_ok(), "error:{:?}", result);
        });
    }

    #[test]
    /// Performance test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: moving-average-convergence-divergence, https://github.com/woonhulktin/HETSA.
    /// data sources: macd/*.dat
    fn test_performance_macd_with_attestation() {
        iterate_over_data(data_dir(MACD_DATA_PATH).as_path(), |data_path| {
            info!("Data path: {}", data_path.to_string_lossy());
            // call the test_template with info flag on,
            // which prints out the time
            let result = test_template::<Vec<f64>>(
                policy_path(MACD_POLICY).as_path(),
                trust_path(CLIENT_CERT).as_path(),
                trust_path(CLIENT_KEY).as_path(),
                Some(program_path(MACD_WASM).to_string_lossy().into_owned().as_str()),
                &[("input-0", data_path.to_string_lossy().into_owned().as_str())],
                &[],
            );
            assert!(result.is_ok(), "error:{:?}", result);
        });
    }

    /// This test was written to test an issue.
    /// The issue was that the key storage in Mbed Crypto was being exhausted
    /// in the proxy attestation server.
    /// The fix was to delete keys after they are used.
    /// This test creates 32 enclaves, each of which attests against the proxy
    /// attestation server.
    /// To generate the dataset for this test:
    /// - Go to directory: sdk/utility/macd2bincode
    /// - execute run.sh . It generates more than 32 datasets of the form *.dat .
    /// - Manually copy all *.dat to sdk/datasets/macd
    #[test]
    #[ignore]
    fn test_multiple_keys() {
        iterate_over_data(data_dir(MACD_DATA_PATH).as_path(), |data_path| {
            // call the test_template with info flag on,
            // which prints out the time
            let result = test_template::<Vec<f64>>(
                policy_path(MULTIPLE_KEY_POLICY).as_path(),
                trust_path(CLIENT_CERT).as_path(),
                trust_path(CLIENT_KEY).as_path(),
                Some(program_path(MACD_WASM).to_string_lossy().into_owned().as_str()),
                &[("input-0", data_path.to_string_lossy().into_owned().as_str())],
                &[],
            );
            assert!(result.is_ok(), "error:{:?}", result);
        });
    }

    #[cfg(not(feature = "icecap"))]
    #[test]
    /// Performance test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: intersection-sum, matching the setting in .
    /// data sources: private-set-inter-sum/*.dat
    fn test_performance_set_intersection_sum_with_attestation() {
        iterate_over_data(data_dir("private-set-inter-sum").as_path(), |data_path| {
            info!("Data path: {}", data_path.display());
            // call the test_template with info flag on,
            // which prints out the time
            let result = test_template::<(usize, u64)>(
                policy_path(PRIVATE_SET_INTER_SUM_POLICY).as_path(),
                trust_path(CLIENT_CERT).as_path(),
                trust_path(CLIENT_KEY).as_path(),
                Some(program_path(INTERSECTION_SET_SUM_WASM).to_string_lossy().into_owned().as_str()),
                &[("input-0", data_path.to_string_lossy().into_owned().as_str())],
                &[],
            );
            assert!(result.is_ok(), "error:{:?}", result);
        });
    }

    /// This is the template of test cases for veracruz-server,
    /// ensuring it is a single client policy,
    /// and the client_cert and client_key match the policy
    /// The type T is the return type of the computation
    fn test_template<T: std::fmt::Debug + serde::de::DeserializeOwned>(
        policy_path: &Path,
        client_cert_path: &Path,
        client_key_path: &Path,
        program_path: Option<&str>,
        // Assuming there is a single data provider,
        // yet the client can provision several packages.
        // The list determines the order of which data is sent out, from head to tail.
        // Each element contains the package id (u64) and the path to the data
        data_id_paths: &[(&str, &str)],
        stream_id_paths: &[(&str, &str)],
    ) -> Result<(), VeracruzServerError> {
        info!("### Step 0.  Initialise test configuration.");
        // initialise the pipe
        let (server_tls_tx, client_tls_rx): (
            std::sync::mpsc::Sender<std::vec::Vec<u8>>,
            std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        ) = std::sync::mpsc::channel();
        let (client_tls_tx, server_tls_rx): (
            std::sync::mpsc::Sender<(u32, std::vec::Vec<u8>)>,
            std::sync::mpsc::Receiver<(u32, std::vec::Vec<u8>)>,
        ) = std::sync::mpsc::channel();

        info!("### Step 1.  Read policy and set up the proxy attestation server.");
        // load the policy, initialise enclave and start tls
        let time_setup = Instant::now();
        let (policy, policy_json, policy_hash) = read_policy(policy_path)?;
        //let debug_flag = policy.debug;
        let ticket = setup(policy.proxy_attestation_server_url().clone());
        info!(
            "             Setup time (μs): {}.",
            time_setup.elapsed().as_micros()
        );
        info!("### Step 2.  Initialise enclave.");
        let time_init = Instant::now();
        let mut veracruz_server = VeracruzServerEnclave::new(&policy_json)?;
        let client_session_id = veracruz_server.new_tls_session().and_then(|id| {
            if id == 0 {
                Err(VeracruzServerError::MissingFieldError("client_session_id"))
            } else {
                Ok(id)
            }
        })?;
        #[cfg(feature = "nitro")]
        let test_target_platform: Platform = Platform::Nitro;
        #[cfg(feature = "sgx")]
        let test_target_platform: Platform = Platform::SGX;
        #[cfg(feature = "tz")]
        let test_target_platform: Platform = Platform::TrustZone;
        #[cfg(feature = "icecap")]
        let test_target_platform: Platform = Platform::IceCap;

        info!("             Enclave generated a self-signed certificate:");

        let mut client_session = create_client_test_session(
            client_cert_path,
            client_key_path,
        )?;
        info!(
            "             Initialasation time (μs): {}.",
            time_init.elapsed().as_micros()
        );

        info!("### Step 3.  Spawn Veracruz server thread.");
        let time_server_boot = Instant::now();
        CONTINUE_FLAG_HASH.lock()?.insert(ticket, true);
        let server_loop_handle = thread::spawn(move || {
            server_tls_loop(&mut veracruz_server, server_tls_tx, server_tls_rx, ticket).map_err(
                |e| {
                    CONTINUE_FLAG_HASH.lock().unwrap().insert(ticket, false);
                    e
                },
            )
        });
        info!(
            "             Booting Veracruz server time (μs): {}.",
            time_server_boot.elapsed().as_micros()
        );

        // Need to clone paths to concreate strings,
        // so the ownership can be transferred into a client thread.
        let program_path: Option<String> = program_path.map(|p| p.to_string());
        // Assuming we are using single data provider,
        // yet the client can provision several packages.
        // The list determines the order of which data is sent out, from head to tail.
        // Each element contains the package id (u64) and the path to the data
        let data_id_paths: Vec<_> = data_id_paths
            .iter()
            .map(|(number, path)| (number.to_string(), path.to_string()))
            .collect();
        let stream_id_paths: Vec<_> = stream_id_paths
            .iter()
            .map(|(number, path)| (number.to_string(), path.to_string()))
            .collect();

        // This is a closure, containing instructions from clients.
        // A sperate thread is spawn and direcly call this closure.
        // However if an Error pop up, the thread set the CONTINUE_FLAG to false,
        // hence stopping the server thread.
        let mut client_body = move || {
            info!(
                "### Step 4.  Client provisions program at {:?}.",
                program_path
            );

            //TODO: change to the actually remote filename
            let program_file_name = if let Some(path) = program_path.as_ref() {
                Path::new(path).file_name().unwrap().to_str().unwrap()
            } else {
                "no_program"
            };
            // if there is a program provided
            if let Some(path) = program_path.as_ref() {
                let time_provosion_data = Instant::now();
                check_policy_hash(
                    &policy_hash,
                    client_session_id,
                    &mut client_session,
                    ticket,
                    &client_tls_tx,
                    &client_tls_rx,
                )?;
                check_runtime_manager_hash(&policy,
                                           &client_session,
                                           &test_target_platform)?;

                let response = provision_program(
                    Path::new(path),
                    client_session_id,
                    &mut client_session,
                    ticket,
                    &client_tls_tx,
                    &client_tls_rx,
                )?;
                info!(
                    "             Client received acknowledgement after sending program: {:?}",
                    transport_protocol::parse_runtime_manager_response(&response)
                );
                info!(
                    "             Provisioning program time (μs): {}.",
                    time_provosion_data.elapsed().as_micros()
                );
            }

            info!("### Step 6.  Data providers provision secret data.");
            for (remote_file_name, data_path) in data_id_paths.iter() {
                info!(
                    "             Data providers provision secret data #{}.",
                    remote_file_name
                );
                let time_data_hash = Instant::now();
                check_policy_hash(
                    &policy_hash,
                    client_session_id,
                    &mut client_session,
                    ticket,
                    &client_tls_tx,
                    &client_tls_rx,
                )?;
                check_runtime_manager_hash(&policy,
                                           &client_session,
                                           &test_target_platform)?;
                info!(
                    "             Data provider hash response time (μs): {}.",
                    time_data_hash.elapsed().as_micros()
                );
                let time_data = Instant::now();
                let response = provision_data(
                    Path::new(data_path),
                    client_session_id,
                    &mut client_session,
                    ticket,
                    &client_tls_tx,
                    &client_tls_rx,
                    remote_file_name,
                )?;
                info!(
                    "             Client received acknowledgement after sending data: {:?},",
                    transport_protocol::parse_runtime_manager_response(&response)
                );
                info!(
                    "             Provisioning data time (μs): {}.",
                    time_data.elapsed().as_micros()
                );
            }
            // If stream_id_paths is NOT empty, we are in streaming mode
            if !stream_id_paths.is_empty() {
                info!("### Step 7.  Stream providers request the program hash.");

                let mut id_vec = Vec::new();
                let mut stream_data_vec = Vec::new();

                for (remote_file_name, data_path) in stream_id_paths.iter() {
                    id_vec.push(remote_file_name);
                    let data = {
                        let mut data_file = std::fs::File::open(data_path)?;
                        let mut data_buffer = std::vec::Vec::new();
                        data_file.read_to_end(&mut data_buffer)?;
                        data_buffer
                    };
                    let decoded_data: Vec<Vec<u8>> = pinecone::from_bytes(&data.as_slice())?;
                    // convert vec of raw stream packages to queue of them
                    stream_data_vec.push(decoded_data);
                }

                check_runtime_manager_hash(&policy,
                                           &client_session,
                                           &test_target_platform)?;

                // Reverse the vec so we can use `pop` for the `first` element of the list.
                // In each round of stream, the loop pops an element from the `stream_data_vec`
                // in the order specified in the package id vec `id_vec`.
                // e.g. if id_vec is [2,1,0], the loop pops stream_data_vec[2] then
                // stream_data_vec[1] and then stream_data_vec[0].
                stream_data_vec.iter_mut().for_each(|e| e.reverse());
                let mut count = 0;
                loop {
                    let next_round_data: Vec<_> = {
                        let next: Vec<_> = stream_data_vec.iter_mut().map(|d| d.pop()).collect();
                        if next.iter().any(|e| e.is_none()) {
                            break;
                        }
                        id_vec
                            .clone()
                            .into_iter()
                            .zip(next.into_iter().flatten())
                            .collect()
                    };
                    info!("------------ Streaming Round # {} ------------", count);
                    count += 1;
                    for (remote_file_name, data) in next_round_data.iter() {
                        let time_stream_hash = Instant::now();
                        check_policy_hash(
                            &policy_hash,
                            client_session_id,
                            &mut client_session,
                            ticket,
                            &client_tls_tx,
                            &client_tls_rx,
                        )?;
                        info!(
                            "             Stream provider hash response time (μs): {}.",
                            time_stream_hash.elapsed().as_micros()
                        );
                        info!(
                            "             Stream provider provision secret data #{}.",
                            remote_file_name
                        );
                        let time_stream = Instant::now();
                        let response = provision_stream(
                            data.as_slice(),
                            client_session_id,
                            &mut client_session,
                            ticket,
                            &client_tls_tx,
                            &client_tls_rx,
                            remote_file_name,
                        )?;
                        info!(
                            "             Stream provider received acknowledgement after sending stream data: {:?},",
                            transport_protocol::parse_runtime_manager_response(&response)
                        );
                        info!(
                            "             Provisioning stream time (μs): {}.",
                            time_stream.elapsed().as_micros()
                        );
                    }
                    info!(
                        "### Step 8.  Result retrievers request program {}.",
                        program_file_name
                    );
                    let time_result_hash = Instant::now();
                    check_policy_hash(
                        &policy_hash,
                        client_session_id,
                        &mut client_session,
                        ticket,
                        &client_tls_tx,
                        &client_tls_rx,
                    )?;
                    check_runtime_manager_hash(&policy,
                                               &client_session,
                                               &test_target_platform)?;
                    info!(
                        "             Result retriever hash response time (μs): {}.",
                        time_result_hash.elapsed().as_micros()
                    );
                    let time_result = Instant::now();
                    info!("             Result retrievers request result.");
                    // NOTE: Fetch result twice on purpose.
                    client_tls_send(
                        &client_tls_tx,
                        &client_tls_rx,
                        client_session_id,
                        &mut client_session,
                        ticket,
                        &transport_protocol::serialize_request_result(program_file_name)?
                            .as_slice(),
                    )
                    .and_then(|response| {
                        // decode the result
                        let response =
                            transport_protocol::parse_runtime_manager_response(&response)?;
                        let response = transport_protocol::parse_result(&response)?;
                        response.ok_or(VeracruzServerError::MissingFieldError(
                            "Result retrievers response",
                        ))
                    })?;
                    let response = client_tls_send(
                        &client_tls_tx,
                        &client_tls_rx,
                        client_session_id,
                        &mut client_session,
                        ticket,
                        &transport_protocol::serialize_request_result(program_file_name)?
                            .as_slice(),
                    )
                    .and_then(|response| {
                        // decode the result
                        let response =
                            transport_protocol::parse_runtime_manager_response(&response)?;
                        let response = transport_protocol::parse_result(&response)?;
                        response.ok_or(VeracruzServerError::MissingFieldError(
                            "Result retrievers response",
                        ))
                    })?;
                    info!(
                        "             Computation result time (μs): {}.",
                        time_result.elapsed().as_micros()
                    );
                    info!("### Step 9.  Client decodes the result.");
                    let result: T = pinecone::from_bytes(&response.as_slice())?;
                    info!("             Client received result: {:?},", result);
                }
                info!("------------ Stream-Result-Next End  ------------");
            } else {
                info!("### Step 7.  NOT in streaming mode.");
                info!(
                    "### Step 8.  Result retrievers request program {}.",
                    program_file_name
                );
                let time_result_hash = Instant::now();
                check_policy_hash(
                    &policy_hash,
                    client_session_id,
                    &mut client_session,
                    ticket,
                    &client_tls_tx,
                    &client_tls_rx,
                )?;

                check_runtime_manager_hash(&policy,
                                           &client_session,
                                           &test_target_platform)?;
                info!(
                    "             Result retriever hash response time (μs): {}.",
                    time_result_hash.elapsed().as_micros()
                );
                let time_result = Instant::now();
                info!("             Result retrievers request result.");
                let response = client_tls_send(
                    &client_tls_tx,
                    &client_tls_rx,
                    client_session_id,
                    &mut client_session,
                    ticket,
                    &transport_protocol::serialize_request_result(program_file_name)?.as_slice(),
                )
                .and_then(|response| {
                    // decode the result
                    let response = transport_protocol::parse_runtime_manager_response(&response)?;
                    let response = transport_protocol::parse_result(&response)?;
                    response.ok_or(VeracruzServerError::MissingFieldError(
                        "Result retrievers response",
                    ))
                })?;
                info!(
                    "             Computation result time (μs): {}.",
                    time_result.elapsed().as_micros()
                );
                info!("### Step 9.  Client decodes the result.");
                let result: T = pinecone::from_bytes(&response.as_slice())?;
                info!("             Client received result: {:?},", result);
            }

            info!("### Step 10. Client shuts down Veracruz.");
            let time_shutdown = Instant::now();
            let response = client_tls_send(
                &client_tls_tx,
                &client_tls_rx,
                client_session_id,
                &mut client_session,
                ticket,
                &transport_protocol::serialize_request_shutdown()?.as_slice(),
            )?;
            info!(
                "             Client received acknowledgment after shutdown request: {:?}",
                transport_protocol::parse_runtime_manager_response(&response)
            );
            info!(
                "             Shutdown time (μs): {}.",
                time_shutdown.elapsed().as_micros()
            );
            Ok::<(), VeracruzServerError>(())
        };

        thread::spawn(move || {
            client_body().map_err(|e| {
                CONTINUE_FLAG_HASH.lock().unwrap().insert(ticket, false);
                e
            })
        })
        .join()
        // double `?` one for join and one for client_body
        .map_err(|e| VeracruzServerError::JoinError(e))??;

        // double `?` one for join and one for client_body
        server_loop_handle
            .join()
            .map_err(|e| VeracruzServerError::JoinError(e))??;
        Ok(())
    }

    /// Auxiliary function: apply functor to all the policy file (json file) in the path
    fn iterate_over_policy(dir_path: &Path, f: fn(&str) -> ()) {
        for entry in dir_path
            .read_dir()
            .expect(&format!("invalid dir path:{}", dir_path.to_string_lossy()))
        {
            if let Ok(entry) = entry {
                if let Some(extension_str) = entry
                    .path()
                    .extension()
                    .and_then(|extension_name| extension_name.to_str())
                {
                    // iterate over all the json file
                    if extension_str.eq_ignore_ascii_case("json") {
                        let policy_path = entry.path();
                        if let Some(policy_filename) = policy_path.to_str() {
                            let policy_json = std::fs::read_to_string(policy_filename)
                                .expect(&format!("Cannot open file {}", policy_filename));
                            f(&policy_json);
                        }
                    }
                }
            }
        }
    }

    fn iterate_over_data(dir_path: &Path, f: fn(&Path) -> ()) {
        for entry in dir_path
            .read_dir()
            .expect(&format!("invalid path:{}", dir_path.to_string_lossy()))
        {
            if let Ok(entry) = entry {
                if let Some(extension_str) = entry
                    .path()
                    .extension()
                    .and_then(|extension_name| extension_name.to_str())
                {
                    // iterate over all the json file
                    if extension_str.eq_ignore_ascii_case("dat") {
                        let data_path = entry.path();
                        f(data_path.as_path());
                    }
                }
            }
        }
    }

    /// Auxiliary function: read policy file
    fn read_policy(fname: &Path) -> Result<(Policy, String, String), VeracruzServerError> {
        let policy_json =
            std::fs::read_to_string(fname).expect(&format!("Cannot open file {}", fname.to_string_lossy()));


        let policy_hash = ring::digest::digest(&ring::digest::SHA256, policy_json.as_bytes());
        let policy_hash_str = hex::encode(&policy_hash.as_ref().to_vec());
        let policy = Policy::from_json(policy_json.as_ref())?;
        Ok((policy, policy_json.to_string(), policy_hash_str))
    }

    /// Auxiliary function: initialise the Veracruz server from policy and open a tls session
    fn init_veracruz_server_and_tls_session(
        policy_json: &str,
    ) -> Result<(VeracruzServerEnclave, u32), VeracruzServerError> {
        let veracruz_server = VeracruzServerEnclave::new(&policy_json)?;

        let one_tenth_sec = std::time::Duration::from_millis(100);
        std::thread::sleep(one_tenth_sec); // wait for the client to start

        veracruz_server.new_tls_session().and_then(|session_id| {
            if session_id != 0 {
                Ok((veracruz_server, session_id))
            } else {
                Err(VeracruzServerError::MissingFieldError("Session id"))
            }
        })
    }

    fn provision_program(
        filename: &Path,
        client_session_id: u32,
        client_session: &mut dyn rustls::Session,
        ticket: u32,
        client_tls_tx: &std::sync::mpsc::Sender<(u32, std::vec::Vec<u8>)>,
        client_tls_rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
    ) -> Result<Vec<u8>, VeracruzServerError> {
        let mut program_file = std::fs::File::open(filename)?;
        let mut program_text = std::vec::Vec::new();

        program_file.read_to_end(&mut program_text)?;

        let serialized_program_text = transport_protocol::serialize_program(
            &program_text,
            Path::new(filename).file_name().unwrap().to_str().unwrap(),
        )?;
        client_tls_send(
            client_tls_tx,
            client_tls_rx,
            client_session_id,
            client_session,
            ticket,
            &serialized_program_text[..],
        )
    }

    fn check_policy_hash(
        expected_policy_hash: &str,
        client_session_id: u32,
        client_session: &mut dyn rustls::Session,
        ticket: u32,
        client_tls_tx: &std::sync::mpsc::Sender<(u32, std::vec::Vec<u8>)>,
        client_tls_rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
    ) -> Result<(), VeracruzServerError> {
        let serialized_request_policy_hash = transport_protocol::serialize_request_policy_hash()?;
        let response = client_tls_send(
            client_tls_tx,
            client_tls_rx,
            client_session_id,
            client_session,
            ticket,
            &serialized_request_policy_hash[..],
        )?;
        let parsed_response = transport_protocol::parse_runtime_manager_response(&response)?;
        let status = parsed_response.get_status();
        if status != transport_protocol::ResponseStatus::SUCCESS {
            return Err(VeracruzServerError::ResponseError(
                "check_policy_hash parse_runtime_manager_response",
                status,
            ));
        }
        let received_hash = std::str::from_utf8(&parsed_response.get_policy_hash().data)?;
        if received_hash == expected_policy_hash {
            return Ok(());
        } else {
            return Err(VeracruzServerError::MismatchError {
                variable: "request_policy_hash",
                received: received_hash.as_bytes().to_vec(),
                expected: expected_policy_hash.as_bytes().to_vec(),
            });
        }
    }

    fn compare_policy_hash(received: &[u8], policy: &Policy, platform: &Platform) -> bool {
        #[cfg(feature = "debug")]
        {
            // don't check hash because the received hash might be zeros (for nitro, for example)
            return true;
        }
        #[cfg(not(feature = "debug"))]
        {
            let expected = match policy.runtime_manager_hash(platform) {
                Err(_) => return false,
                Ok(data) => data,
            };
            let expected_bytes = match hex::decode(expected) {
                Err(_) => return false,
                Ok(bytes) => bytes,
            };
    
            if &received[..] != expected_bytes.as_slice() {
                return false;
            } else {
                return true;
            }
        }
    }

    fn check_runtime_manager_hash(policy: &Policy,
                                  client_session: &dyn rustls::Session,
                                  test_target_platform: &Platform,
    ) -> Result<(), VeracruzServerError> {
        match client_session.get_peer_certificates() {
            None => {
                return Err(VeracruzServerError::MissingFieldError("NO PEER CERTIFICATES. WTF?"));
            },
            Some(certs) => {
                let ee_cert = webpki::EndEntityCert::from(certs[0].as_ref()).unwrap();
                let ues = ee_cert.unrecognized_extensions();
                // check for OUR extension
                let encoded_extension_id: [u8; 3] = [VERACRUZ_RUNTIME_HASH_EXTENSION_ID[0] * 40 + VERACRUZ_RUNTIME_HASH_EXTENSION_ID[1],
                                                     VERACRUZ_RUNTIME_HASH_EXTENSION_ID[2],
                                                     VERACRUZ_RUNTIME_HASH_EXTENSION_ID[3]];
                match ues.get(&encoded_extension_id[..]) {
                    None => {
                        println!("Our extension is not present. This should be fatal");
                        return Err(VeracruzServerError::MissingFieldError("MY CRAZY CUSTOM EXTENSION AIN'T TERE"));
                    },
                    Some(data) => {
                        let extension_data = data.read_all(VeracruzServerError::MissingFieldError("CAN'T READ MY CRAZY CUSTOM EXTENSION"), |input| {
                            Ok(input.read_bytes_to_end())
                        })?;
                        if !compare_policy_hash(extension_data.as_slice_less_safe(), &policy, test_target_platform) {
                               // The hashes didn't match
                               println!("None of the hashes matched.");
                               return Err(VeracruzServerError::InvalidRuntimeManagerHash);
                        }
                        return Ok(());
                    }
                }
            }
        }
    }

    fn provision_data(
        filename: &Path,
        client_session_id: u32,
        client_session: &mut rustls::ClientSession,
        ticket: u32,
        client_tls_tx: &std::sync::mpsc::Sender<(u32, std::vec::Vec<u8>)>,
        client_tls_rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        remote_file_name: &str,
    ) -> Result<Vec<u8>, VeracruzServerError> {
        // The client also sends the associated data
        let data = {
            let mut data_file = std::fs::File::open(filename)?;
            let mut data_buffer = std::vec::Vec::new();
            data_file.read_to_end(&mut data_buffer)?;
            data_buffer
        };
        let serialized_data = transport_protocol::serialize_program_data(&data, remote_file_name)?;

        client_tls_send(
            client_tls_tx,
            client_tls_rx,
            client_session_id,
            client_session,
            ticket,
            &serialized_data[..],
        )
    }

    fn provision_stream(
        data: &[u8],
        client_session_id: u32,
        client_session: &mut rustls::ClientSession,
        ticket: u32,
        client_tls_tx: &std::sync::mpsc::Sender<(u32, std::vec::Vec<u8>)>,
        client_tls_rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        remote_file_name: &str,
    ) -> Result<Vec<u8>, VeracruzServerError> {
        // The client also sends the associated data
        let serialized_stream = transport_protocol::serialize_stream(data, remote_file_name)?;

        client_tls_send(
            client_tls_tx,
            client_tls_rx,
            client_session_id,
            client_session,
            ticket,
            &serialized_stream[..],
        )
    }

    fn server_tls_loop(
        veracruz_server: &mut dyn veracruz_server::VeracruzServer,
        tx: std::sync::mpsc::Sender<std::vec::Vec<u8>>,
        rx: std::sync::mpsc::Receiver<(u32, std::vec::Vec<u8>)>,
        ticket: u32,
    ) -> Result<(), VeracruzServerError> {
        while *CONTINUE_FLAG_HASH.lock()?.get(&ticket).ok_or(
            VeracruzServerError::MissingFieldError("CONTINUE_FLAG_HASH ticket"),
        )? {
            let received = rx.try_recv();
            let (session_id, received_buffer) = received.unwrap_or_else(|_| (0, Vec::new()));

            if received_buffer.len() > 0 {
                let (active_flag, output_data_option) =
                    veracruz_server.tls_data(session_id, received_buffer)?;
                let output_data = output_data_option.unwrap_or_else(|| Vec::new());
                for output in output_data.iter() {
                    if output.len() > 0 {
                        tx.send(output.clone())?;
                    }
                }
                if !active_flag {
                    return Ok(());
                }
            }
        }
        Err(VeracruzServerError::DirectStrError(
            "No message arrives server",
        ))
    }

    fn client_tls_send(
        tx: &std::sync::mpsc::Sender<(u32, std::vec::Vec<u8>)>,
        rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        session_id: u32,
        session: &mut dyn rustls::Session,
        ticket: u32,
        send_data: &[u8],
    ) -> Result<Vec<u8>, VeracruzServerError> {
        session.write_all(&send_data)?;

        let mut output: std::vec::Vec<u8> = std::vec::Vec::new();

        session.write_tls(&mut output)?;

        tx.send((session_id, output))?;

        while *CONTINUE_FLAG_HASH.lock()?.get(&ticket).ok_or(
            VeracruzServerError::MissingFieldError("CONTINUE_FLAG_HASH ticket"),
        )? {
            let received = rx.try_recv();

            if received.is_ok() && (!session.is_handshaking() || session.wants_read()) {
                let received = received?;

                let mut slice = &received[..];
                session.read_tls(&mut slice)?;
                session.process_new_packets()?;

                let mut received_buffer: std::vec::Vec<u8> = std::vec::Vec::new();

                let num_bytes = session.read_to_end(&mut received_buffer)?;
                if num_bytes > 0 {
                    return Ok(received_buffer);
                }
            } else if session.wants_write() {
                let mut output: std::vec::Vec<u8> = std::vec::Vec::new();
                session.write_tls(&mut output)?;
                let _res = tx.send((session_id, output))?;
            }
        }
        Err(VeracruzServerError::DirectStrError(
            "Terminate due to server crash",
        ))
    }

    fn create_client_test_session(
        client_cert_filename: &Path,
        client_key_filename: &Path,
    ) -> Result<rustls::ClientSession, VeracruzServerError> {
        let client_cert = read_cert_file(client_cert_filename)?;

        let client_priv_key = read_priv_key_file(client_key_filename)?;

        let proxy_service_cert = {
            let data = std::fs::read(trust_path(CA_CERT).as_path()).unwrap();
            let certs = rustls::internal::pemfile::certs(&mut data.as_slice()).unwrap();
            certs[0].clone()
        };
        let mut client_config = rustls::ClientConfig::new();
        let mut client_cert_vec = std::vec::Vec::new();
        client_cert_vec.push(client_cert);
        client_config.set_single_client_cert(client_cert_vec, client_priv_key);
        client_config
            .root_store
            .add(&proxy_service_cert).unwrap();

        let dns_name = webpki::DNSNameRef::try_from_ascii_str("ComputeEnclave.dev")?;
        Ok(rustls::ClientSession::new(
            &std::sync::Arc::new(client_config),
            dns_name,
        ))
    }

    fn read_cert_file(filename: &Path) -> Result<rustls::Certificate, VeracruzServerError> {
        let mut cert_file = std::fs::File::open(filename)?;
        let mut cert_buffer = std::vec::Vec::new();
        cert_file.read_to_end(&mut cert_buffer)?;
        let mut cursor = std::io::Cursor::new(cert_buffer);
        let certs = rustls::internal::pemfile::certs(&mut cursor)
            .map_err(|_| VeracruzServerError::TLSUnspecifiedError)?;
        if certs.len() == 0 {
            Err(VeracruzServerError::InvalidLengthError("certs.len()", 1))
        } else {
            Ok(certs[0].clone())
        }
    }

    fn read_priv_key_file(filename: &Path) -> Result<rustls::PrivateKey, VeracruzServerError> {
        let mut key_file = std::fs::File::open(filename)?;
        let mut key_buffer = std::vec::Vec::new();
        key_file.read_to_end(&mut key_buffer)?;
        let mut cursor = std::io::Cursor::new(key_buffer);
        let rsa_keys = rustls::internal::pemfile::rsa_private_keys(&mut cursor)
            .map_err(|_| VeracruzServerError::TLSUnspecifiedError)?;
        Ok(rsa_keys[0].clone())
    }
}
