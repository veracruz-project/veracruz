//! Veracruz test material
//!
//! One of the main Veracruz integration tests, as lots of material is imported
//! directly or indirectly, here.
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

#[cfg(test)]
mod tests {
    // Policies
    const SINGLE_CLIENT_POLICY: &'static str = "single_client.json";
    const LINEAR_REGRESSION_DUAL_POLICY: &'static str = "dual_policy.json";
    const LINEAR_REGRESSION_TRIPLE_POLICY: &'static str = "triple_policy_1.json";
    const LINEAR_REGRESSION_PARALLEL_POLICY: &'static str = "dual_parallel_policy.json";
    const INTERSECTION_SET_SUM_TRIPLE_POLICY: &'static str = "triple_policy_2.json";
    const PERMUTED_INTERSECTION_SET_SUM_TRIPLE_POLICY: &'static str = "triple_policy_3.json";
    const STRING_EDIT_DISTANCE_TRIPLE_POLICY: &'static str = "triple_policy_4.json";
    const STRING_EDIT_DISTANCE_QUADRUPLE_POLICY: &'static str = "quadruple_policy.json";

    // Identities
    const CA_CERT: &'static str = "CACert.pem";
    const CA_KEY: &'static str = "CAKey.pem";
    const PROGRAM_CLIENT_CERT: &'static str = "program_client_cert.pem";
    const PROGRAM_CLIENT_KEY: &'static str = "program_client_key.pem";
    const RESULT_CLIENT_CERT: &'static str = "result_client_cert.pem";
    const RESULT_CLIENT_KEY: &'static str = "result_client_key.pem";
    const CLIENT_CERT: &'static str = "client_rsa_cert.pem";
    const CLIENT_KEY: &'static str = "client_rsa_key.pem";
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

    use actix_rt::System;
    use async_std::task;
    use either::{Left, Right};
    use env_logger;
    use err_derive::Error;
    use log::info;
    use policy_utils::policy::Policy;
    use proxy_attestation_server;
    use std::{
        env::{self, VarError},
        future::Future,
        io::Read,
        path::{Path, PathBuf},
        sync::Once,
        time::Duration,
    };
    use veracruz_client;
    use veracruz_server;

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
    pub fn data_path(filename: &str) -> PathBuf {
        PathBuf::from(env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()))
            .join(filename)
    }

    #[derive(Debug, Error)]
    pub enum VeracruzTestError {
        #[error(display = "VeracruzTest: IOError: {:?}.", _0)]
        IOError(#[error(source)] std::io::Error),
        #[error(display = "VeracruzTest: Postcard Error: {:?}.", _0)]
        PostcardError(#[error(source)] postcard::Error),
        #[error(display = "VeracruzTest: VeracruzClientError: {:?}.", _0)]
        VeracruzClientError(#[error(source)] veracruz_client::VeracruzClientError),
        #[error(display = "VeracruzTest: PolicyError: {:?}.", _0)]
        VeracruzUtilError(#[error(source)] policy_utils::error::PolicyError),
        #[error(display = "VeracruzTest: VeracruzServerError: {:?}.", _0)]
        VeracruzServerError(#[error(source)] veracruz_server::VeracruzServerError),
        #[error(display = "VeracruzTest: TransportProtocolError: {:?}.", _0)]
        TransportProtocolError(#[error(source)] transport_protocol::TransportProtocolError),
        #[error(display = "VeracruzTest: Failed to find client with index {}.", _0)]
        ClientIndexError(usize),
    }

    /// A wrapper to force tests to panic after a timeout.
    ///
    /// Note this is overrideable with the VERACRUZ_TEST_TIMEOUT environment
    /// variable, which provides a timeout in seconds
    pub async fn timeout<F: Future>(timeout: Duration, f: F) -> <F as Future>::Output {
        let timeout = match env::var("VERACRUZ_TEST_TIMEOUT")
            .map_err(Left)
            .and_then(|timeout| timeout.parse::<u64>().map_err(Right))
        {
            Ok(val) => Duration::from_secs(val),
            Err(Left(VarError::NotPresent)) => timeout,
            Err(err) => panic!("Couldn't parse VERACRUZ_TEST_TIMEOUT: {:?}", err),
        };

        match actix_web::rt::time::timeout(timeout, f).await {
            Ok(r) => r,
            Err(_) => panic!(
                "timeout after {:?}, specify VERACRUZ_TEST_TIMEOUT to override",
                timeout
            ),
        }
    }

    static SETUP: Once = Once::new();

    pub fn setup(proxy_attestation_server_url: String) {
        SETUP.call_once(|| {
            info!("SETUP.call_once called");
            std::env::set_var("RUST_LOG", "debug,actix_server=info,actix_web=info,tokio_reactor=info,hyper=info,reqwest=info,rustls=info");

            env_logger::builder().init();
            let _main_loop_handle = std::thread::spawn(|| {
                let sys = System::new();
                let server = proxy_attestation_server::server::server(
                    proxy_attestation_server_url,
                    trust_path(CA_CERT),
                    trust_path(CA_KEY),
                    false).unwrap();
                sys.block_on(server).unwrap();
            });
        });
    }

    fn read_binary_file(filename: &Path) -> Result<Vec<u8>, VeracruzTestError> {
        let data = {
            let mut data_file = std::fs::File::open(&filename)?;
            let mut data_buffer = std::vec::Vec::new();
            data_file.read_to_end(&mut data_buffer)?;
            data_buffer
        };
        return Ok(data.clone());
    }

    /// A test of veracruz using network communication using a single session
    #[actix_rt::test]
    async fn veracruz_phase1_get_random_one_client() {
        timeout(Duration::from_secs(1200), async {
            let result = test_template(
                policy_path(SINGLE_CLIENT_POLICY),
                &vec![(trust_path(CLIENT_CERT), trust_path(CLIENT_KEY))],
                &[(
                    0,
                    "/program/random-source.wasm",
                    program_path(RANDOM_SOURCE_WASM),
                )],
                &vec![],
                &vec![(0, "/output/random.dat")],
            )
            .await;
            assert!(
                result.is_ok(),
                "veracruz_phase1_get_random_one_client failed with error: {:?}",
                result
            );
        })
        .await
    }

    /// A test of veracruz using network communication using two sessions (one for program and one for data)
    #[actix_rt::test]
    async fn veracruz_phase1_linear_regression_two_clients() {
        timeout(Duration::from_secs(1200), async {
            let result = test_template(
                policy_path(LINEAR_REGRESSION_DUAL_POLICY),
                &vec![
                    (
                        trust_path(PROGRAM_CLIENT_CERT),
                        trust_path(PROGRAM_CLIENT_KEY),
                    ),
                    (trust_path(DATA_CLIENT_CERT), trust_path(DATA_CLIENT_KEY)),
                ],
                &[(
                    0,
                    "/program/linear-regression.wasm",
                    program_path(LINEAR_REGRESSION_WASM),
                )],
                &vec![(
                    1,
                    "/input/linear-regression.dat",
                    data_path(LINEAR_REGRESSION_DATA),
                )],
                &vec![(1, "/output/linear-regression.dat")],
            )
            .await;
            assert!(
                result.is_ok(),
                "veracruz_phase1_linear_regression_one_client failed with error: {:?}",
                result
            );
        })
        .await
    }

    /// A test of veracruz using network communication using three sessions (one for program, one for data, and one for retrieval)
    #[actix_rt::test]
    async fn veracruz_phase2_linear_regression_three_clients() {
        timeout(Duration::from_secs(1200), async {
            let result = test_template(
                policy_path(LINEAR_REGRESSION_TRIPLE_POLICY),
                &vec![
                    (
                        trust_path(PROGRAM_CLIENT_CERT),
                        trust_path(PROGRAM_CLIENT_KEY),
                    ),
                    (trust_path(DATA_CLIENT_CERT), trust_path(DATA_CLIENT_KEY)),
                    (
                        trust_path(RESULT_CLIENT_CERT),
                        trust_path(RESULT_CLIENT_KEY),
                    ),
                ],
                &[(
                    0,
                    "/program/linear-regression.wasm",
                    program_path(LINEAR_REGRESSION_WASM),
                )],
                &vec![(
                    1,
                    "/input/linear-regression.dat",
                    data_path(LINEAR_REGRESSION_DATA),
                )],
                &vec![
                    (1, "/output/linear-regression.dat"),
                    (2, "/output/linear-regression.dat"),
                ],
            )
            .await;
            assert!(
                result.is_ok(),
                "veracruz_phase2_linear_regression_three_clients failed with error: {:?}",
                result
            );
        })
        .await
    }

    /// A test of veracruz using network communication using four sessions
    /// (one for program, one for the first data, and one for the second data and retrieval.)
    #[actix_rt::test]
    #[ignore] // FIXME: test currently disabled because it fails on IceCap
    async fn veracruz_phase2_intersection_set_sum_three_clients() {
        timeout(Duration::from_secs(1200), async {
            let result = test_template(
                policy_path(INTERSECTION_SET_SUM_TRIPLE_POLICY),
                &vec![
                    (
                        trust_path(PROGRAM_CLIENT_CERT),
                        trust_path(PROGRAM_CLIENT_KEY),
                    ),
                    (trust_path(DATA_CLIENT_CERT), trust_path(DATA_CLIENT_KEY)),
                    (
                        trust_path(RESULT_CLIENT_CERT),
                        trust_path(RESULT_CLIENT_KEY),
                    ),
                ],
                &[(
                    0,
                    "/program/intersection-set-sum.wasm",
                    program_path(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
                )],
                &vec![
                    (
                        1,
                        "/input/intersection-advertisement-viewer.dat",
                        data_path(INTERSECTION_SET_SUM_ADVERTISEMENT_DATA),
                    ),
                    (
                        2,
                        "/input/intersection-customer.dat",
                        data_path(INTERSECTION_SET_SUM_CUSTOMER_DATA),
                    ),
                ],
                &vec![(2, "/output/intersection-set-sum.dat")],
            )
            .await;
            assert!(
                result.is_ok(),
                "veracruz_phase2_intersection_set_sum_two_clients failed with error: {:?}",
                result
            );
        })
        .await
    }

    /// A test of veracruz using network communication using four sessions
    /// (one for program, one for the first data, and one for the second data and retrieval.)
    #[actix_rt::test]
    #[ignore] // FIXME: test currently disabled because it fails on IceCap
    async fn veracruz_phase2_intersection_set_sum_two_clients_reversed_data_provision() {
        timeout(Duration::from_secs(1200), async {
        let result = test_template(
            policy_path(PERMUTED_INTERSECTION_SET_SUM_TRIPLE_POLICY),
            &vec![
                (
                    trust_path(PROGRAM_CLIENT_CERT),
                    trust_path(PROGRAM_CLIENT_KEY),
                ),
                (trust_path(DATA_CLIENT_CERT), trust_path(DATA_CLIENT_KEY)),
                (
                    trust_path(RESULT_CLIENT_CERT),
                    trust_path(RESULT_CLIENT_KEY),
                ),
            ],
            &[(
                0,
                "/program/intersection-set-sum.wasm",
                program_path(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
            )],
            &vec![
                (
                    2,
                    "/input/intersection-customer.dat",
                    data_path(INTERSECTION_SET_SUM_CUSTOMER_DATA),
                ),
                (
                    1,
                    "/input/intersection-advertisement-viewer.dat",
                    data_path(INTERSECTION_SET_SUM_ADVERTISEMENT_DATA),
                ),
            ],
            &vec![(2, "/output/intersection-set-sum.dat")],
        )
        .await;
        assert!(result.is_ok(), "veracruz_phase2_intersection_set_sum_two_clients_reversed_data_provision failed with error: {:?}",result);
      }).await
    }

    /// A test of veracruz using network communication using three sessions
    /// (one for program, one for the first data, and one for the second data and retrieval.)
    #[actix_rt::test]
    async fn veracruz_phase2_string_edit_distance_three_clients() {
        timeout(Duration::from_secs(1200), async {
            let result = test_template(
                policy_path(STRING_EDIT_DISTANCE_TRIPLE_POLICY),
                &vec![
                    (
                        trust_path(PROGRAM_CLIENT_CERT),
                        trust_path(PROGRAM_CLIENT_KEY),
                    ),
                    (trust_path(DATA_CLIENT_CERT), trust_path(DATA_CLIENT_KEY)),
                    (
                        trust_path(RESULT_CLIENT_CERT),
                        trust_path(RESULT_CLIENT_KEY),
                    ),
                ],
                &[(
                    0,
                    "/program/string-edit-distance.wasm",
                    program_path(STRING_EDIT_DISTANCE_WASM),
                )],
                &vec![
                    (1, "/input/hello-world-1.dat", data_path(STRING_1_DATA)),
                    (2, "/input/hello-world-2.dat", data_path(STRING_2_DATA)),
                ],
                &vec![(2, "/output/string-edit-distance.dat")],
            )
            .await;
            assert!(
                result.is_ok(),
                "veracruz_phase2_string_edit_distance_three_clients failed with error: {:?}",
                result
            );
        })
        .await
    }

    /// A test of veracruz using network communication using four sessions
    /// (one for program, one for the first data, one for the second data, and one for retrieval.)
    #[actix_rt::test]
    async fn veracruz_phase3_string_edit_distance_four_clients() {
        timeout(Duration::from_secs(1200), async {
            let result = test_template(
                policy_path(STRING_EDIT_DISTANCE_QUADRUPLE_POLICY),
                &vec![
                    (
                        trust_path(PROGRAM_CLIENT_CERT),
                        trust_path(PROGRAM_CLIENT_KEY),
                    ),
                    (trust_path(DATA_CLIENT_CERT), trust_path(DATA_CLIENT_KEY)),
                    (
                        trust_path(DATA_CLIENT_SECOND_CERT),
                        trust_path(DATA_CLIENT_SECOND_KEY),
                    ),
                    (
                        trust_path(RESULT_CLIENT_CERT),
                        trust_path(RESULT_CLIENT_KEY),
                    ),
                ],
                &[(
                    0,
                    "/program/string-edit-distance.wasm",
                    program_path(STRING_EDIT_DISTANCE_WASM),
                )],
                &vec![
                    (1, "/input/hello-world-1.dat", data_path(STRING_1_DATA)),
                    (2, "/input/hello-world-2.dat", data_path(STRING_2_DATA)),
                ],
                &vec![(3, "/output/string-edit-distance.dat")],
            )
            .await;
            assert!(
                result.is_ok(),
                "veracruz_phase3_string_edit_distance_four_clients failed with error: {:?}",
                result
            );
        })
        .await
    }

    /// a test of veracruz using network communication using two parallel sessions
    /// (one for program, one for data sending and retrieving)
    #[actix_rt::test]
    async fn veracruz_phase4_linear_regression_two_clients_parallel() {
        timeout(Duration::from_secs(1200), async {
            let policy_json =
                read_policy(policy_path(LINEAR_REGRESSION_PARALLEL_POLICY).as_path()).unwrap();
            let policy = Policy::from_json(&policy_json).unwrap();

            setup(policy.proxy_attestation_server_url().clone());

            task::sleep(std::time::Duration::from_millis(5000)).await;
            let policy_file = policy_path(LINEAR_REGRESSION_PARALLEL_POLICY);
            let server_handle = server_tls_loop(policy_file.as_path());

            let program_provider_handle = async {
                task::sleep(std::time::Duration::from_millis(10000)).await;
                info!("### program provider start.");
                let mut client = veracruz_client::VeracruzClient::new(
                    trust_path(PROGRAM_CLIENT_CERT).as_path(),
                    trust_path(PROGRAM_CLIENT_KEY).as_path(),
                    &policy_json,
                )?;
                let prog_path = program_path(LINEAR_REGRESSION_WASM);
                info!("### program provider read binary.");
                let program_data = read_binary_file(prog_path.as_path())?;
                info!("### program provider send binary.");
                client.send_program("/program/linear-regression.wasm", &program_data)?;
                Ok::<(), VeracruzTestError>(())
            };
            let data_provider_handle = async {
                task::sleep(std::time::Duration::from_millis(15000)).await;
                info!("### data provider start.");
                let mut client = veracruz_client::VeracruzClient::new(
                    trust_path(DATA_CLIENT_CERT).as_path(),
                    trust_path(DATA_CLIENT_KEY).as_path(),
                    &policy_json,
                )?;

                let data_filename = data_path(LINEAR_REGRESSION_DATA);
                info!("### data provider read input.");
                let data = read_binary_file(&data_filename.as_path())?;
                info!("### data provider send input.");
                client.send_data("/input/linear-regression.dat", &data)?;
                info!("### data provider read result.");
                client.request_compute("/program/linear-regression.wasm")?;
                client.get_results("/output/linear-regression.dat")?;
                info!("### data provider request shutdown.");
                client.request_shutdown()?;
                Ok::<(), VeracruzTestError>(())
            };

            let result = futures::future::try_join3(
                server_handle,
                program_provider_handle,
                data_provider_handle,
            )
            .await;
            assert!(result.is_ok(), "error: {:?}", result);
        })
        .await
    }

    async fn test_template<P: AsRef<Path>>(
        // Policy files
        policy_path: P,
        // List of client's certificates and private keys
        client_configs: &[(P, P)],
        // Program provider, index refering to the `client_configs` parameter, and program path
        program_providers: &[(usize, &str, P)],
        // Data providers, a list of indices refering to the `client_configs` parameter,
        // remote file name and data pathes.
        // The list determines the order of which data is sent out, from head to tail.
        // Note that a client might provision more than one packages
        data_providers: &[(usize, &str, P)],
        // Result retriever, a list of indices refering to the `client_configs` parameter.
        result_retrievers: &[(usize, &str)],
    ) -> Result<(), VeracruzTestError> {
        let policy_path = policy_path.as_ref();
        let policy_json = read_policy(policy_path)?;
        let policy = Policy::from_json(&policy_json)?;
        setup(policy.proxy_attestation_server_url().clone());
        info!(
            "### Step 0. Read the policy file {}.",
            policy_path.to_string_lossy()
        );

        // Wait the setup
        task::sleep(std::time::Duration::from_millis(5000)).await;

        let server_handle = server_tls_loop(policy_path);

        let clients_handle = async {
            // Wait for the enclave initialasation
            task::sleep(std::time::Duration::from_millis(10000)).await;

            info!("### Step 2. Set up all client sessions.");
            let mut clients = Vec::new();
            for (cert, key) in client_configs.iter() {
                clients.push(veracruz_client::VeracruzClient::new(
                    cert.as_ref(),
                    key.as_ref(),
                    &policy_json,
                )?);
            }
            info!("### Step 3. Provisions programs.");
            for (program_provider_index, remote_filename, data_filename) in program_providers.iter()
            {
                let data_filename = data_filename.as_ref();
                info!(
                    "            Client #{} provisions program {}.",
                    program_provider_index, remote_filename
                );
                let program_provider_veracruz_client = clients
                    .get_mut(*program_provider_index)
                    .ok_or(VeracruzTestError::ClientIndexError(*program_provider_index))?;
                let data = read_binary_file(data_filename)?;
                program_provider_veracruz_client.send_data(remote_filename, &data)?;
            }
            info!("### Step 4. Provision data.");
            // provosion data
            for (data_provider_index, remote_filename, data_filename) in data_providers.iter() {
                let data_filename = data_filename.as_ref();
                info!(
                    "            Client #{} provisions data {}.",
                    data_provider_index, remote_filename
                );
                let data_provider_veracruz_client = clients
                    .get_mut(*data_provider_index)
                    .ok_or(VeracruzTestError::ClientIndexError(*data_provider_index))?;
                let data = read_binary_file(data_filename)?;
                data_provider_veracruz_client.send_data(remote_filename, &data)?;
            }

            info!("### Step 5. Retrieve result and gracefully shutdown the server.");
            for (program_provider_index, remote_filename, _) in program_providers.iter() {
                info!(
                    "            Client #{} request computation {}.",
                    program_provider_index, remote_filename
                );
                let program_provider_veracruz_client = clients
                    .get_mut(*program_provider_index)
                    .ok_or(VeracruzTestError::ClientIndexError(*program_provider_index))?;
                program_provider_veracruz_client.request_compute(remote_filename)?;
            }
            for (result_retriever_index, remote_filename) in result_retrievers.iter() {
                info!(
                    "            Client #{} request result {}.",
                    result_retriever_index, remote_filename
                );
                let result_retriever_veracruz_client = clients
                    .get_mut(*result_retriever_index)
                    .ok_or(VeracruzTestError::ClientIndexError(*result_retriever_index))?;
                let result = result_retriever_veracruz_client.get_results(remote_filename)?;
                info!("            Result of len: {:?}", result.len());
            }

            clients
                .get_mut(0)
                .ok_or(VeracruzTestError::ClientIndexError(0))?
                .request_shutdown()?;
            info!("            Client 0 successfully issued shutdown command");
            Ok::<(), VeracruzTestError>(())
        };
        info!("            Server and clients threads execute.");
        let _ = futures::try_join!(server_handle, clients_handle)?;
        info!("### Step 6. Server and clients threads join.");
        Ok(())
    }

    async fn server_tls_loop(policy_filename: &Path) -> Result<(), VeracruzTestError> {
        let policy_text = read_policy(policy_filename)?;
        veracruz_server::server::server(&policy_text)?.await?;
        Ok(())
    }

    fn read_policy(policy_filename: &Path) -> Result<String, VeracruzTestError> {
        let policy_text = std::fs::read_to_string(policy_filename).expect(&format!(
            "Cannot open file {}",
            policy_filename.to_string_lossy()
        ));

        return Ok(policy_text);
    }
}
