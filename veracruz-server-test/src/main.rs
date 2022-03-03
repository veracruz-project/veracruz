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
    use env_logger;
    use lazy_static::lazy_static;
    use log::{debug, error, info, Level};
    use policy_utils::{policy::Policy, Platform};
    use proxy_attestation_server;
    use ring;
    use std::{
        collections::HashMap,
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
    use transport_protocol;
    use veracruz_server::veracruz_server::*;
    #[cfg(feature = "icecap")]
    use veracruz_server::VeracruzServerIceCap as VeracruzServerEnclave;
    #[cfg(feature = "linux")]
    use veracruz_server::VeracruzServerLinux as VeracruzServerEnclave;
    #[cfg(feature = "nitro")]
    use veracruz_server::VeracruzServerNitro as VeracruzServerEnclave;
    use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;

    // Policy files
    const POLICY: &'static str = "single_client.json";
    const NO_DEBUG_POLICY: &'static str = "single_client_no_debug.json";
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

    static SETUP: Once = Once::new();
    static DEBUG_SETUP: Once = Once::new();
    lazy_static! {
        // This is a semi-hack to test of if the debug is called.
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
            info!("SETUP.call_once called");

            let _main_loop_handle = std::thread::spawn(|| {
                let mut sys = System::new("Veracruz Proxy Attestation Server");
                println!(
                    "spawned thread calling server with url:{:?}",
                    proxy_attestation_server_url
                );
                #[cfg(feature = "debug")]
                let server = proxy_attestation_server::server::server(
                    proxy_attestation_server_url,
                    trust_path(CA_CERT).as_path(),
                    trust_path(CA_KEY).as_path(),
                    true,
                )
                .unwrap();
                #[cfg(not(feature = "debug"))]
                let server = proxy_attestation_server::server::server(
                    proxy_attestation_server_url,
                    trust_path(CA_CERT).as_path(),
                    trust_path(CA_KEY).as_path(),
                    false,
                )
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
                    if record.level() == Level::Debug && message.contains("Enclave debug message") {
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
        let policy_dir = PathBuf::from(
            env::var("VERACRUZ_POLICY_DIR")
                .unwrap_or("../test-collateral".to_string())
                .clone(),
        );
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
        let policy_dir = PathBuf::from(
            env::var("VERACRUZ_POLICY_DIR")
                .unwrap_or("../test-collateral".to_string())
                .clone(),
        );
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
        let policy_dir = PathBuf::from(
            env::var("VERACRUZ_POLICY_DIR")
                .unwrap_or("../test-collateral".to_string())
                .clone(),
        );
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
        let (policy, policy_json, _) = read_policy(policy_path(POLICY)).unwrap();
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
        test_template(
            policy_path(NO_DEBUG_POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/linear-regression.wasm",
                program_path(LINEAR_REGRESSION_WASM),
            )],
            &[(
                "/input/linear-regression.dat",
                data_dir(LINEAR_REGRESSION_DATA),
            )],
            &[],
            &["/output/linear-regression.dat"],
        )
        .unwrap();
        assert!(!DEBUG_IS_CALLED.load(Ordering::SeqCst));
    }

    #[test]
    /// Attempt to establish a client session with the Veracruz server with an invalid client certificate
    fn test_phase2_single_session_with_invalid_client_certificate() {
        let (policy, policy_json, _) = read_policy(policy_path(POLICY)).unwrap();
        // start the proxy attestation server
        setup(policy.proxy_attestation_server_url().clone());
        init_veracruz_server_and_tls_session(&policy_json).unwrap();

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
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[("/program/read-file.wasm", program_path(READ_FILE_WASM))],
            &[("/input/hello-world-1.dat", data_dir(STRING_1_DATA))],
            &[],
            &["/output/test/test.txt", "/output/hello-world-1.dat"],
        )
        .unwrap();
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: random-source, returning a vec of random u8
    /// data sources: none
    fn test_phase2_random_source_no_data_no_attestation() {
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/random-source.wasm",
                program_path(RANDOM_SOURCE_WASM),
            )],
            &[],
            &[],
            &["/output/random.dat"],
        )
        .unwrap();
    }

    #[test]
    /// Attempt to fetch the result without program nor data
    fn test_phase2_random_source_no_program_no_data() {
        let result = test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[],
            &[],
            &[],
            &["/output/random.dat"],
        );

        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Attempt to provision a wrong program
    fn test_phase2_incorrect_program_no_attestation() {
        let result = test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/string-edit-distance.wasm",
                program_path(STRING_EDIT_DISTANCE_WASM),
            )],
            &[],
            &[],
            &["/output/random.dat"],
        );

        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Attempt to use an unauthorized key
    fn test_phase2_random_source_no_data_no_attestation_unauthorized_key() {
        let result = test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(UNAUTHORIZED_KEY),
            &[(
                "/program/random-source.wasm",
                program_path(RANDOM_SOURCE_WASM),
            )],
            &[],
            &[],
            &["/output/random.dat"],
        );

        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Attempt to use an unauthorized certificate
    fn test_phase2_random_source_no_data_no_attestation_unauthorized_certificate() {
        let result = test_template(
            policy_path(POLICY),
            trust_path(UNAUTHORIZED_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/random-source.wasm",
                program_path(RANDOM_SOURCE_WASM),
            )],
            &[],
            &[],
            &["/output/random.dat"],
        );

        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// A unauthorized client attempted to connect the service
    fn test_phase2_random_source_no_data_no_attestation_unauthorized_client() {
        let result = test_template(
            policy_path(POLICY),
            trust_path(UNAUTHORIZED_CERT),
            trust_path(UNAUTHORIZED_KEY),
            &[(
                "/program/random-source.wasm",
                program_path(RANDOM_SOURCE_WASM),
            )],
            &[],
            &[],
            &["/output/random.dat"],
        );

        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: linear regression, computing the gradient and intercept,
    /// i.e. the LinearRegression struct, given a series of point in the
    /// two-dimensional space.  Data sources: linear-regression, a vec of points
    /// in two-dimensional space, represented by Vec<(f64, f64)>.
    fn test_phase2_linear_regression_single_data_no_attestation() {
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/linear-regression.wasm",
                program_path(LINEAR_REGRESSION_WASM),
            )],
            &[(
                "/input/linear-regression.dat",
                data_dir(LINEAR_REGRESSION_DATA),
            )],
            &[],
            &["/output/linear-regression.dat"],
        )
        .unwrap();
    }

    #[test]
    /// Attempt to fetch result without data
    fn test_phase2_linear_regression_no_data_no_attestation() {
        let result = test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/linear-regression.wasm",
                program_path(LINEAR_REGRESSION_WASM),
            )],
            &[],
            &[],
            &["/output/linear-regression.dat"],
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
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/intersection-set-sum.wasm",
                program_path(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
            )],
            &[
                // message sends out in the reversed order
                (
                    "/input/intersection-customer.dat",
                    data_dir(INTERSECTION_SET_SUM_CUSTOMER_DATA),
                ),
                (
                    "/input/intersection-advertisement-viewer.dat",
                    data_dir(INTERSECTION_SET_SUM_ADVERTISEMENT_DATA),
                ),
            ],
            &[],
            &["/output/intersection-set-sum.dat"],
        )
        .unwrap();
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: string-edit-distance, computing the string edit distance.
    /// data sources: two strings
    fn test_phase2_string_edit_distance_two_data_no_attestation() {
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/string-edit-distance.wasm",
                program_path(STRING_EDIT_DISTANCE_WASM),
            )],
            &[
                ("/input/hello-world-1.dat", data_dir(STRING_1_DATA)),
                ("/input/hello-world-2.dat", data_dir(STRING_2_DATA)),
            ],
            &[],
            &["/output/string-edit-distance.dat"],
        )
        .unwrap();
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: linear regression, computing the gradient and intercept,
    /// i.e. the LinearRegression struct, given a series of point in the
    /// two-dimensional space. Data sources: linear-regression, a vec of points
    /// in two-dimensional space, represented by Vec<(f64, f64)>
    /// A standard one data source scenario with attestation.
    fn test_phase3_linear_regression_one_data_with_attestation() {
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/linear-regression.wasm",
                program_path(LINEAR_REGRESSION_WASM),
            )],
            &[(
                "/input/linear-regression.dat",
                data_dir(LINEAR_REGRESSION_DATA),
            )],
            &[],
            &["/output/linear-regression.dat"],
        )
        .unwrap();
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: set intersection, computing the intersection of two sets of persons.
    /// data sources: two vecs of persons, representing by Vec<Person>
    /// A standard two data sources scenario with attestation.
    fn test_phase3_private_set_intersection_two_data_with_attestation() {
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/private-set-intersection.wasm",
                program_path(PERSON_SET_INTERSECTION_WASM),
            )],
            &[
                ("/input/private-set-1.dat", data_dir(PERSON_SET_1_DATA)),
                ("/input/private-set-2.dat", data_dir(PERSON_SET_2_DATA)),
            ],
            &[],
            &["/output/private-set.dat"],
        )
        .unwrap();
    }

    #[test]
    /// Integration test:
    /// policy: PiProvider, DataProvider, StreamProvider and ResultReader is the same party
    /// computation: sum of an initial f64 number and two streams of f64 numbers.
    /// data sources: an initial f64 value, and two vecs of f64, representing two streams.
    /// A standard one data source and two stream sources scenario with attestation.
    fn test_phase4_number_stream_accumulation_one_data_two_stream_with_attestation() {
        let stream_list =
            stream_list(data_dir(F64_STREAM_PATH), "/input").expect("Failed to parse input");
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/number-stream-accumulation.wasm",
                program_path(NUMBER_STREM_WASM),
            )],
            &[("/input/number-stream-init.dat", data_dir(SINGLE_F64_DATA))],
            &stream_list,
            &["/output/accumulation.dat"],
        )
        .unwrap();
    }

    #[test]
    /// Attempt to fetch result without enough stream data.
    fn test_phase4_number_stream_accumulation_one_data_one_stream_with_attestation() {
        let result = test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/number-stream-accumulation.wasm",
                program_path(NUMBER_STREM_WASM),
            )],
            &[("/input/number-stream-init.dat", data_dir(SINGLE_F64_DATA))],
            &[],
            &["/output/accumulation.dat"],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Attempt to provision stream data in the state of loading static data.
    fn test_phase4_number_stream_accumulation_no_data_two_stream_with_attestation() {
        let stream_list =
            stream_list(data_dir(F64_STREAM_PATH), "/input").expect("Failed to parse input");
        let result = test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/number-stream-accumulation.wasm",
                program_path(NUMBER_STREM_WASM),
            )],
            &[],
            &stream_list,
            &["/output/accumulation.dat"],
        );
        assert!(result.is_err(), "An error should occur");
    }

    #[test]
    /// Attempt to provision stream data in the state of loading static data.
    fn test_phase4_native_postcard_module() {
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/postcard-native.wasm",
                program_path(POSTCARD_NATIVE_WASM),
            )],
            &[("/input/postcard.dat", data_dir(POSTCARD_DATA))],
            &[],
            &["/output/postcard_native.txt"],
        )
        .unwrap();
    }

    #[test]
    /// Attempt to provision stream data in the state of loading static data.
    fn test_phase4_wasm_postcard_module() {
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[("/program/postcard-wasm.wasm", program_path(POSTCARD_WASM))],
            &[("/input/postcard.dat", data_dir(POSTCARD_DATA))],
            &[],
            &["/output/postcard_wasm.txt"],
        )
        .unwrap();
    }

    #[test]
    /// Performance test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: logistic regression, https://github.com/kimandrik/IDASH2017.
    /// data sources: idash2017/*.dat
    fn test_performance_idash2017_with_attestation() {
        let input_vec = input_list(
            data_dir(LOGISTICS_REGRESSION_DATA_PATH),
            "/input/idash2017/",
        )
        .expect("Failed to parse input");
        let input_vec: Vec<(&str, PathBuf)> =
            input_vec.iter().map(|(s, k)| (&s[..], k.clone())).collect();

        let result = test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/idash2017-logistic-regression.wasm",
                program_path(LOGISTICS_REGRESSION_WASM),
            )],
            &input_vec,
            &[],
            // only read two outputs
            &[
                "/output/idash2017/generate-data-0.dat",
                "/output/idash2017/generate-data-1.dat",
            ],
        );
        assert!(result.is_ok(), "error:{:?}", result);
    }

    #[test]
    /// Performance test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: moving-average-convergence-divergence, https://github.com/woonhulktin/HETSA.
    /// data sources: macd/*.dat
    fn test_performance_macd_with_attestation() {
        let input_vec =
            input_list(data_dir(MACD_DATA_PATH), "/input/macd/").expect("Failed to parse input");
        let input_vec: Vec<(&str, PathBuf)> =
            input_vec.iter().map(|(s, k)| (&s[..], k.clone())).collect();

        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/moving-average-convergence-divergence.wasm",
                program_path(MACD_WASM),
            )],
            &input_vec,
            &[],
            &["/output/macd/generate-1000.dat"],
        )
        .unwrap();
    }

    #[test]
    /// Performance test:
    /// policy: PiProvider, DataProvider and ResultReader is the same party
    /// computation: intersection-sum, matching the setting in .
    /// data sources: private-set-inter-sum/*.dat
    fn test_performance_set_intersection_sum_with_attestation() {
        let input_vec = input_list(
            data_dir(PRIVATE_SET_INTER_SUM_DATA_PATH),
            "/input/private-set-inter-sum/",
        )
        .expect("Failed to parse input");
        let input_vec: Vec<(&str, PathBuf)> =
            input_vec.iter().map(|(s, k)| (&s[..], k.clone())).collect();

        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[(
                "/program/private-set-intersection-sum.wasm",
                program_path(INTERSECTION_SET_SUM_WASM),
            )],
            &input_vec,
            &[],
            &["/output/private-set-inter-sum/data-2000-0"],
        )
        .unwrap();
    }

    #[test]
    fn test_fd_create() {
        test_template(
            policy_path(POLICY),
            trust_path(CLIENT_CERT),
            trust_path(CLIENT_KEY),
            &[("/program/fd-create.wasm", program_path(FD_CREATE_RUST_WASM))],
            &[],
            &[],
            &["/output/pass"],
        )
        .unwrap();
    }

    /// This is the template of test cases for veracruz-server,
    /// ensuring it is a single client policy,
    /// and the client_cert and client_key match the policy
    /// The type T is the return type of the computation
    fn test_template<P: AsRef<Path>>(
        policy_path: P,
        client_cert_path: P,
        client_key_path: P,
        program_path: &[(&str, P)],
        // Assuming there is a single data provider,
        // yet the client can provision several packages.
        // The list determines the order of which data is sent out, from head to tail.
        // Each element contains the package id (u64) and the path to the data
        data_id_paths: &[(&str, P)],
        stream_id_paths: &[Vec<(String, P)>],
        output_files: &[&str],
    ) -> Result<(), VeracruzServerError> {
        let policy_path = policy_path.as_ref();
        let client_cert_path = client_cert_path.as_ref();
        let client_key_path = client_key_path.as_ref();
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

        #[cfg(feature = "linux")]
        let test_target_platform: Platform = Platform::Linux;
        #[cfg(feature = "nitro")]
        let test_target_platform: Platform = Platform::Nitro;
        #[cfg(feature = "icecap")]
        let test_target_platform: Platform = Platform::IceCap;

        info!("             Enclave generated a self-signed certificate:");

        let mut client_session = create_client_test_session(client_cert_path, client_key_path)?;
        info!(
            "             Initialization time (μs): {}.",
            time_init.elapsed().as_micros()
        );

        info!("### Step 3.  Spawn Veracruz server thread.");
        let time_server_boot = Instant::now();
        CONTINUE_FLAG_HASH.lock()?.insert(ticket, true);
        let server_loop_handle = thread::spawn(move || {
            server_tls_loop(&mut veracruz_server, server_tls_tx, server_tls_rx, ticket).map_err(
                |e| {
                    eprintln!("AAAAAAAAAAAAAAH {:?}", e);
                    CONTINUE_FLAG_HASH.lock().unwrap().insert(ticket, false);
                    e
                },
            )
        });
        info!(
            "             Booting Veracruz server time (μs): {}.",
            time_server_boot.elapsed().as_micros()
        );

        // Need to clone paths to concrete strings,
        // so the ownership can be transferred into a client thread.
        let program_path: Vec<_> = program_path
            .iter()
            .map(|(remote_path, path)| (remote_path.to_string(), path.as_ref().to_path_buf()))
            .collect();
        // Assuming we are using single data provider,
        // yet the client can provision several packages.
        // The list determines the order of which data is sent out, from head to tail.
        // Each element contains the package id (u64) and the path to the data
        let data_id_paths: Vec<_> = data_id_paths
            .iter()
            .map(|(remote_path, path)| (remote_path.to_string(), path.as_ref().to_path_buf()))
            .collect();
        let mut stream_id_paths: Vec<_> = stream_id_paths
            .iter()
            .map(|v| {
                v.iter()
                    .map(|(remote_path, path)| {
                        (remote_path.to_string(), path.as_ref().to_path_buf())
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let output_files: Vec<_> = output_files.iter().map(|path| path.to_string()).collect();

        // This is a closure, containing instructions from clients.
        // A separate thread is spawn and directly call this closure.
        // However if an Error pop up, the thread set the CONTINUE_FLAG to false,
        // hence stopping the server thread.
        let mut client_body = move || {
            info!(
                "### Step 4.  Client provisions program at {:?}.",
                program_path
            );

            for (remote_file_name, data_path) in program_path.iter() {
                let time_provision_data = Instant::now();

                check_hash(
                    &policy,
                    &policy_hash,
                    &test_target_platform,
                    client_session_id,
                    &mut client_session,
                    ticket,
                    &client_tls_tx,
                    &client_tls_rx,
                )?;

                let response = provision_data(
                    Path::new(data_path),
                    client_session_id,
                    &mut client_session,
                    ticket,
                    &client_tls_tx,
                    &client_tls_rx,
                    &remote_file_name,
                )?;
                info!(
                    "             Client received acknowledgement after sending program: {:?}",
                    transport_protocol::parse_runtime_manager_response(None, &response)
                );
                info!(
                    "             Provisioning program time (μs): {}.",
                    time_provision_data.elapsed().as_micros()
                );
            }

            info!("### Step 6.  Data providers provision secret data.");
            for (remote_file_name, data_path) in data_id_paths.iter() {
                info!(
                    "             Data providers provision secret data {}.",
                    remote_file_name
                );
                let time_data_hash = Instant::now();
                check_hash(
                    &policy,
                    &policy_hash,
                    &test_target_platform,
                    client_session_id,
                    &mut client_session,
                    ticket,
                    &client_tls_tx,
                    &client_tls_rx,
                )?;
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
                    transport_protocol::parse_runtime_manager_response(None, &response)
                );
                info!(
                    "             Provisioning data time (μs): {}.",
                    time_data.elapsed().as_micros()
                );
            }
            // If stream_id_paths is empty, we inject an round of stream with empty data
            if stream_id_paths.is_empty() {
                stream_id_paths.push(Vec::new());
            }

            info!("### Step 7.  Stream providers request the program hash.");
            for (round, paths) in stream_id_paths.iter().enumerate() {
                info!(
                    "             ------------ Streaming Round # {} ------------",
                    round
                );
                for (remote_file_name, data_path) in paths.iter() {
                    info!(
                        "             Stream providers provision secret data {}.",
                        remote_file_name
                    );
                    let time_data_hash = Instant::now();
                    check_hash(
                        &policy,
                        &policy_hash,
                        &test_target_platform,
                        client_session_id,
                        &mut client_session,
                        ticket,
                        &client_tls_tx,
                        &client_tls_rx,
                    )?;
                    info!(
                        "             Stream provider hash response time (μs): {}.",
                        time_data_hash.elapsed().as_micros()
                    );
                    let time_data = Instant::now();
                    let response = provision_stream(
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
                        transport_protocol::parse_runtime_manager_response(None, &response)
                    );
                    info!(
                        "             Provisioning data time (μs): {}.",
                        time_data.elapsed().as_micros()
                    );
                }
                for (remote_file_name, _) in program_path.iter() {
                    info!(
                        "### Step 8.  Result retrievers request program {}.",
                        remote_file_name
                    );
                    let time_result_hash = Instant::now();
                    check_hash(
                        &policy,
                        &policy_hash,
                        &test_target_platform,
                        client_session_id,
                        &mut client_session,
                        ticket,
                        &client_tls_tx,
                        &client_tls_rx,
                    )?;
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
                        &transport_protocol::serialize_request_result(remote_file_name)?.as_slice(),
                    )?;
                    info!(
                        "             Computation result time (μs): {} with return code (undecoded) {:?}.",
                        time_result.elapsed().as_micros(), response
                    );
                }

                info!("### Step 9.  Client read and decodes the result.");
                for remote_file_name in &output_files {
                    info!("             Read {}.", remote_file_name);
                    let response = read_file(
                        client_session_id,
                        &mut client_session,
                        ticket,
                        &client_tls_tx,
                        &client_tls_rx,
                        &remote_file_name,
                    )?;
                    let response =
                        transport_protocol::parse_runtime_manager_response(None, &response)?;
                    let response = transport_protocol::parse_result(&response)?;
                    let result = response.ok_or(VeracruzServerError::MissingFieldError(
                        "Result retrievers response",
                    ))?;
                    info!(
                        "             Client received result of len: {:?},",
                        result.len()
                    );
                }
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
                transport_protocol::parse_runtime_manager_response(None, &response)
            );
            info!(
                "             Shutdown time (μs): {}.",
                time_shutdown.elapsed().as_micros()
            );
            Ok::<(), VeracruzServerError>(())
        };

        info!("Preparing to spawn client body thread.");

        let _response = thread::spawn(move || {
            client_body().map_err(|e| {
                CONTINUE_FLAG_HASH.lock().unwrap().insert(ticket, false);
                e
            })
        })
        .join()
        // double `?` one for join and one for client_body
        .map_err(|e| VeracruzServerError::JoinError(e))??;

        info!("Client body thread launched.");

        // double `?` one for join and one for client_body
        server_loop_handle
            .join()
            .map_err(|e| VeracruzServerError::JoinError(e))??;

        info!("Server thread launched.");

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

    /// Function produces a vec of pairs of remote (des) file and local (src) file path,
    /// which corresponds to provisioning/overwriting the content of the local file to the remote file.
    /// Read all files and diretory in the path of 'dir_path' in the local machine and replace the prefix with 'remote_dir_path'.
    /// E.g. if call the function with '/local/path/' and '/remote/path/',
    /// the result could be [(/remote/path/a.txt, /local/path/a.txt), (/remote/path/b/c.txt, /local/path/b/c.txt), ... ].
    fn input_list<T: AsRef<Path>, K: AsRef<Path>>(
        dir_path: T,
        remote_dir_path: K,
    ) -> Result<Vec<(String, PathBuf)>, VeracruzServerError> {
        let mut rst = Vec::new();
        let dir_path = dir_path.as_ref();
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
                rst.append(&mut input_list(entry, remote_entry_path)?)
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
        Ok(rst)
    }

    /// Function produces a vec of input lists. Each list corresponds to a round
    /// and is a vec of pairs of remote (des) file and local (src) file path,
    /// which corresponds to provisioning/appending the content of the local file to the remote file.
    fn stream_list<T: AsRef<Path>, K: AsRef<Path>>(
        dir_path: T,
        remote_dir_path: K,
    ) -> Result<Vec<Vec<(String, PathBuf)>>, VeracruzServerError> {
        let remote_dir_path = remote_dir_path.as_ref();
        let mut rst = Vec::new();
        let dir_path = dir_path.as_ref();
        let mut dir_entries = dir_path
            .read_dir()
            .expect(&format!("invalid path: {:?}", dir_path))
            .filter_map(|e| e.map(|x| x.path()).ok())
            .collect::<Vec<_>>();
        dir_entries.sort();
        for entry in dir_entries.iter() {
            rst.push(input_list(entry, remote_dir_path)?);
        }
        Ok(rst)
    }

    /// Auxiliary function: read policy file
    fn read_policy<T: AsRef<Path>>(
        fname: T,
    ) -> Result<(Policy, String, String), VeracruzServerError> {
        let fname = fname.as_ref();
        let policy_json = std::fs::read_to_string(fname)
            .expect(&format!("Cannot open file {}", fname.to_string_lossy()));

        let policy_hash = ring::digest::digest(&ring::digest::SHA256, policy_json.as_bytes());
        let policy_hash_str = hex::encode(&policy_hash.as_ref().to_vec());
        let policy = Policy::from_json(policy_json.as_ref())?;
        Ok((policy, policy_json.to_string(), policy_hash_str))
    }

    /// Auxiliary function: initialise the Veracruz server from policy and open a tls session
    fn init_veracruz_server_and_tls_session(
        policy_json: &str,
    ) -> Result<(VeracruzServerEnclave, u32), VeracruzServerError> {
        let mut veracruz_server = VeracruzServerEnclave::new(&policy_json)?;

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

    fn check_hash(
        policy: &Policy,
        policy_hash: &str,
        test_target_platform: &Platform,
        client_session_id: u32,
        client_session: &mut dyn rustls::Session,
        ticket: u32,
        client_tls_tx: &std::sync::mpsc::Sender<(u32, std::vec::Vec<u8>)>,
        client_tls_rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
    ) -> Result<(), VeracruzServerError> {
        check_policy_hash(
            policy_hash,
            client_session_id,
            client_session,
            ticket,
            client_tls_tx,
            client_tls_rx,
        )?;
        info!("Policy hash OK...");
        check_runtime_manager_hash(policy, client_session, test_target_platform)?;
        Ok(())
    }

    fn check_policy_hash(
        expected_policy_hash: &str,
        client_session_id: u32,
        client_session: &mut dyn rustls::Session,
        ticket: u32,
        client_tls_tx: &std::sync::mpsc::Sender<(u32, std::vec::Vec<u8>)>,
        client_tls_rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
    ) -> Result<(), VeracruzServerError> {
        info!("Serializing policy hash request.");

        let serialized_request_policy_hash = transport_protocol::serialize_request_policy_hash()
            .map_err(|e| {
                error!(
                    "Failed to serialize request for policy hash.  Error produced: {:?}.",
                    e
                );

                e
            })?;

        let response = client_tls_send(
            client_tls_tx,
            client_tls_rx,
            client_session_id,
            client_session,
            ticket,
            &serialized_request_policy_hash[..],
        )
        .map_err(|e| {
            error!("Failed to send TLS data.  Error produced: {:?}.", e);

            e
        })?;

        info!("Reponse received: {:?}", response);

        let parsed_response = transport_protocol::parse_runtime_manager_response(None, &response)?;
        let status = parsed_response.get_status();

        if status != transport_protocol::ResponseStatus::SUCCESS {
            error!("Received non-Success status: {:?}.", status);
            return Err(VeracruzServerError::ResponseError(
                "check_policy_hash parse_runtime_manager_response",
                status,
            ));
        }
        let received_hash = std::str::from_utf8(&parsed_response.get_policy_hash().data)?;
        info!("Received {:?} as hash.", received_hash);
        return if received_hash == expected_policy_hash {
            info!("Hash matches expected hash ({:?}).", expected_policy_hash);
            Ok(())
        } else {
            error!(
                "Hash does not match expected hash ({:?}).",
                expected_policy_hash
            );
            Err(VeracruzServerError::MismatchError {
                variable: "request_policy_hash",
                received: received_hash.as_bytes().to_vec(),
                expected: expected_policy_hash.as_bytes().to_vec(),
            })
        };
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

            info!("Comparing runtime manager hash {:?} (from policy) against {:?} (received) for platform {:?}.", expected_bytes, received, platform);

            if &received[..] != expected_bytes.as_slice() {
                error!("Runtime manager hash does not match.");

                return false;
            } else {
                info!("Runtime manager hash matches.");

                return true;
            }
        }
    }

    fn check_runtime_manager_hash(
        policy: &Policy,
        client_session: &dyn rustls::Session,
        test_target_platform: &Platform,
    ) -> Result<(), VeracruzServerError> {
        return match client_session.get_peer_certificates() {
            None => {
                error!("No peer certificate found.");

                Err(VeracruzServerError::MissingFieldError(
                    "NO PEER CERTIFICATES. WTF?",
                ))
            }
            Some(certs) => {
                let ee_cert = webpki::EndEntityCert::from(certs[0].as_ref()).unwrap();
                let ues = ee_cert.unrecognized_extensions();

                // check for OUR extension
                let encoded_extension_id: [u8; 3] = [
                    VERACRUZ_RUNTIME_HASH_EXTENSION_ID[0] * 40
                        + VERACRUZ_RUNTIME_HASH_EXTENSION_ID[1],
                    VERACRUZ_RUNTIME_HASH_EXTENSION_ID[2],
                    VERACRUZ_RUNTIME_HASH_EXTENSION_ID[3],
                ];
                match ues.get(&encoded_extension_id[..]) {
                    None => {
                        error!("Our certificate extension is not present.");

                        Err(VeracruzServerError::MissingFieldError(
                            "MY CRAZY CUSTOM EXTENSION AIN'T THERE",
                        ))
                    }
                    Some(data) => {
                        info!("Certificate extension found.");

                        let extension_data = data.read_all(
                            VeracruzServerError::MissingFieldError(
                                "CAN'T READ MY CRAZY CUSTOM EXTENSION",
                            ),
                            |input| Ok(input.read_bytes_to_end()),
                        )?;

                        if !compare_policy_hash(
                            extension_data.as_slice_less_safe(),
                            &policy,
                            test_target_platform,
                        ) {
                            error!("None of the runtime manager hashes matched.");

                            return Err(VeracruzServerError::InvalidRuntimeManagerHash);
                        }
                        Ok(())
                    }
                }
            }
        };
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
        let serialized_data = transport_protocol::serialize_write_file(&data, remote_file_name)?;

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
        let serialized_stream = transport_protocol::serialize_stream(&data, remote_file_name)?;

        client_tls_send(
            client_tls_tx,
            client_tls_rx,
            client_session_id,
            client_session,
            ticket,
            &serialized_stream[..],
        )
    }

    fn read_file(
        client_session_id: u32,
        client_session: &mut rustls::ClientSession,
        ticket: u32,
        client_tls_tx: &std::sync::mpsc::Sender<(u32, std::vec::Vec<u8>)>,
        client_tls_rx: &std::sync::mpsc::Receiver<std::vec::Vec<u8>>,
        remote_file_name: &str,
    ) -> Result<Vec<u8>, VeracruzServerError> {
        // The client also sends the associated data
        let serialized_read = transport_protocol::serialize_read_file(remote_file_name)?;
        client_tls_send(
            client_tls_tx,
            client_tls_rx,
            client_session_id,
            client_session,
            ticket,
            &serialized_read[..],
        )
    }

    fn server_tls_loop(
        veracruz_server: &mut dyn veracruz_server::VeracruzServer,
        tx: std::sync::mpsc::Sender<std::vec::Vec<u8>>,
        rx: std::sync::mpsc::Receiver<(u32, std::vec::Vec<u8>)>,
        ticket: u32,
    ) -> Result<(), VeracruzServerError> {
        info!("Inside server TLS loop...");

        while *CONTINUE_FLAG_HASH
            .lock()
            .map_err(|e| {
                error!(
                    "Failed to obtain lock on CONTINUE_FLAG_HASH.  Error produced: {:?}.",
                    e
                );
                e
            })?
            .get(&ticket)
            .ok_or(VeracruzServerError::MissingFieldError(
                "CONTINUE_FLAG_HASH ticket",
            ))?
        {
            let received = rx.try_recv();
            let (session_id, received_buffer) = received.unwrap_or_else(|_| (0, Vec::new()));

            if received_buffer.len() > 0 {
                let (active_flag, output_data_option) = veracruz_server
                    .tls_data(session_id, received_buffer)
                    .map_err(|e| {
                        error!("Failed to send TLS data.  Error produced: {:?}.", e);
                        e
                    })?;
                let output_data = output_data_option.unwrap_or_else(|| Vec::new());

                for output in output_data.iter() {
                    if output.len() > 0 {
                        tx.send(output.clone()).map_err(|e| {
                            error!(
                                "Failed to send data on TX channel.  Error produced: {:?}.",
                                e
                            );
                            e
                        })?;
                    }
                }

                if !active_flag {
                    info!("VeracruzServer TLS loop dieing due to lack of TLS data.");
                    return Ok(());
                }
            }
        }
        error!("VeracruzServer TLS loop dieing due to no activity...");

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
        session.write_all(&send_data).map_err(|e| {
            error!("Failed to send all data.  Error produced: {:?}.", e);
            e
        })?;

        let mut output: std::vec::Vec<u8> = std::vec::Vec::new();

        session.write_tls(&mut output).map_err(|e| {
            error!("Failed to write TLS.  Error produced: {:?}.", e);
            e
        })?;

        tx.send((session_id, output)).map_err(|e| {
            error!(
                "Failed to send data on TX channel.  Error produced: {:?}.",
                e
            );
            e
        })?;

        while *CONTINUE_FLAG_HASH
            .lock()
            .map_err(|e| {
                error!(
                    "Failed to obtain lock on CONTINUE_FLAG_HASH.  Error produced: {:?}.",
                    e
                );
                e
            })?
            .get(&ticket)
            .ok_or(VeracruzServerError::MissingFieldError(
                "CONTINUE_FLAG_HASH ticket",
            ))?
        {
            let received = rx.try_recv();

            if received.is_ok() && (!session.is_handshaking() || session.wants_read()) {
                info!("Received is OK, and we're not handshaking...");

                let received = received.map_err(|e| {
                    error!("Invariant failed.  Received was not OK.");
                    e
                })?;

                let mut slice = &received[..];
                session.read_tls(&mut slice).map_err(|e| {
                    error!("Failed to read TLS.  Error produced: {:?}.", e);
                    e
                })?;
                session.process_new_packets().map_err(|e| {
                    error!("Failed to process new packets.  Error produced: {:?}.", e);
                    e
                })?;

                let mut received_buffer: std::vec::Vec<u8> = std::vec::Vec::new();

                let num_bytes = session.read_to_end(&mut received_buffer).map_err(|e| {
                    error!("Failed to read data to end.  Error produced: {:?}.", e);
                    e
                })?;

                if num_bytes > 0 {
                    info!("Finished sending via TLS.");
                    return Ok(received_buffer);
                }
            } else if session.wants_write() {
                info!("Session wants write...");
                let mut output: std::vec::Vec<u8> = std::vec::Vec::new();
                session.write_tls(&mut output).map_err(|e| {
                    error!("Failed to write TLS.  Error produced: {:?}.", e);
                    e
                })?;
                let _res = tx.send((session_id, output)).map_err(|e| {
                    error!(
                        "Failed to send data on TX channel.  Error produced: {:?}.",
                        e
                    );
                    e
                })?;
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
            let data = std::fs::read(trust_path(CA_CERT)).unwrap();
            let certs = rustls::internal::pemfile::certs(&mut data.as_slice()).unwrap();
            certs[0].clone()
        };
        let mut client_config = rustls::ClientConfig::new();
        let mut client_cert_vec = std::vec::Vec::new();
        client_cert_vec.push(client_cert);
        client_config.set_single_client_cert(client_cert_vec, client_priv_key);
        client_config.root_store.add(&proxy_service_cert).unwrap();

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
