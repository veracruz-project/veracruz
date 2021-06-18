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
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

// NB: added to avoid a compile failure in Rust's futures library.
#![feature(proc_macro_hygiene)]

#[cfg(test)]
mod tests {
    // Policies
    const GET_RANDOM_POLICY: &'static str = "../test-collateral/get_random_policy.json";
    const LINEAR_REGRESSION_DUAL_POLICY: &'static str = "../test-collateral/dual_policy.json";
    const LINEAR_REGRESSION_TRIPLE_POLICY: &'static str = "../test-collateral/triple_policy.json";
    const LINEAR_REGRESSION_PARALLEL_POLICY: &'static str =
        "../test-collateral/dual_parallel_policy.json";
    const INTERSECTION_SET_SUM_TRIPLE_POLICY: &'static str =
        "../test-collateral/triple_parties_two_data_sources_sum_policy.json";
    const PERMUTED_INTERSECTION_SET_SUM_TRIPLE_POLICY: &'static str =
        "../test-collateral/permuted_triple_parties_two_data_sources_sum_policy.json";
    const STRING_EDIT_DISTANCE_TRIPLE_POLICY: &'static str =
        "../test-collateral/triple_parties_two_data_sources_string_edit_distance_policy.json";
    const STRING_EDIT_DISTANCE_QUADRUPLE_POLICY: &'static str =
        "../test-collateral/quadruple_policy.json";

    // Clients
    const PROGRAM_CLIENT_CERT: &'static str = "../test-collateral/program_client_cert.pem";
    const PROGRAM_CLIENT_KEY: &'static str = "../test-collateral/program_client_key.pem";
    const RESULT_CLIENT_CERT: &'static str = "../test-collateral/result_client_cert.pem";
    const RESULT_CLIENT_KEY: &'static str = "../test-collateral/result_client_key.pem";
    const CLIENT_CERT: &'static str = "../test-collateral/client_rsa_cert.pem";
    const CLIENT_KEY: &'static str = "../test-collateral/client_rsa_key.pem";
    const DATA_CLIENT_CERT: &'static str = "../test-collateral/data_client_cert.pem";
    const DATA_CLIENT_KEY: &'static str = "../test-collateral/data_client_key.pem";
    const DATA_CLIENT_SECOND_CERT: &'static str = "../test-collateral/never_used_cert.pem";
    const DATA_CLIENT_SECOND_KEY: &'static str = "../test-collateral/never_used_key.pem";

    // Programs
    const CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM: &'static str =
        "../test-collateral/intersection-set-sum.wasm";
    const STRING_EDIT_DISTANCE_WASM: &'static str = "../test-collateral/string-edit-distance.wasm";
    const LINEAR_REGRESSION_WASM: &'static str = "../test-collateral/linear-regression.wasm";

    // Data
    const LINEAR_REGRESSION_DATA: &'static str = "../test-collateral/linear-regression.dat";
    const INTERSECTION_SET_SUM_CUSTOMER_DATA: &'static str =
        "../test-collateral/intersection-customer.dat";
    const INTERSECTION_SET_SUM_ADVERTISEMENT_DATA: &'static str =
        "../test-collateral/intersection-advertisement-viewer.dat";
    const STRING_1_DATA: &'static str = "../test-collateral/hello-world-1.dat";
    const STRING_2_DATA: &'static str = "../test-collateral/hello-world-2.dat";

    use actix_rt::System;
    use async_std::task;
    use veracruz_client;
    use env_logger;
    use err_derive::Error;
    use log::info;
    use serde::Deserialize;
    use veracruz_server;
    use std::{io::Read, sync::Once, path::Path};
    use proxy_attestation_server;
    use veracruz_utils::{platform::Platform, policy::policy::Policy};

    #[derive(Debug, Error)]
    pub enum VeracruzTestError {
        #[error(display = "VeracruzTest: IOError: {:?}.", _0)]
        IOError(#[error(source)] std::io::Error),
        #[error(display = "VeracruzTest: Pinecone Error: {:?}.", _0)]
        PineconeError(#[error(source)] pinecone::Error),
        #[error(display = "VeracruzTest: VeracruzClientError: {:?}.", _0)]
        VeracruzClientError(#[error(source)] veracruz_client::VeracruzClientError),
        #[error(display = "VeracruzTest: PolicyError: {:?}.", _0)]
        VeracruzUtilError(#[error(source)] veracruz_utils::policy::error::PolicyError),
        #[error(display = "VeracruzTest: VeracruzServerError: {:?}.", _0)]
        VeracruzServerError(#[error(source)] veracruz_server::VeracruzServerError),
        #[error(display = "VeracruzTest: TransportProtocolError: {:?}.", _0)]
        TransportProtocolError(#[error(source)] transport_protocol::TransportProtocolError),
        #[error(display = "VeracruzTest: Failed to find client with index {}.", _0)]
        ClientIndexError(usize),
    }

    static SETUP: Once = Once::new();

    pub fn setup(proxy_attestation_server_url: String) {
        SETUP.call_once(|| {
            info!("SETUP.call_once called");
            std::env::set_var("RUST_LOG", "debug,actix_server=info,actix_web=info,tokio_reactor=info,hyper=info,reqwest=info,rustls=info");
            env_logger::builder().init();
            let _main_loop_handle = std::thread::spawn(|| {
                let mut sys = System::new("Veracruz Proxy Attestation Server");
                let server = proxy_attestation_server::server::server(proxy_attestation_server_url, false).unwrap();
                sys.block_on(server).unwrap();
            });
        });
    }

    fn read_binary_file(filename: &str) -> Result<Vec<u8>, VeracruzTestError> {
        let data = {
            let mut data_file = std::fs::File::open(filename)?;
            let mut data_buffer = std::vec::Vec::new();
            data_file.read_to_end(&mut data_buffer)?;
            data_buffer
        };
        return Ok(data.clone());
    }

    /// A test of veracruz using network communication using a single session
    #[actix_rt::test]
    async fn veracruz_phase1_get_random_one_client() {
        let result = test_template::<Vec<u8>>(
            GET_RANDOM_POLICY,
            &vec![(CLIENT_CERT, CLIENT_KEY)],
            (0, "../test-collateral/random-source.wasm"),
            &vec![],
            &vec![0],
        )
        .await;
        assert!(
            result.is_ok(),
            "veracruz_phase1_get_random_one_client failed with error: {:?}",
            result
        );
    }

    #[derive(Debug, Deserialize)]
    struct LinearRegression {
        /// Gradient of the linear relationship.
        gradient: f64,
        /// Y-intercept of the linear relationship.
        intercept: f64,
    }

    /// A test of veracruz using network communication using two sessions (one for program and one for data)
    #[actix_rt::test]
    async fn veracruz_phase1_linear_regression_two_clients() {
        let result = test_template::<LinearRegression>(
            LINEAR_REGRESSION_DUAL_POLICY,
            &vec![
                (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
                (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
            ],
            (0, LINEAR_REGRESSION_WASM),
            &vec![(1, "input-0", LINEAR_REGRESSION_DATA)],
            &vec![1],
        )
        .await;
        assert!(
            result.is_ok(),
            "veracruz_phase1_linear_regression_one_client failed with error: {:?}",
            result
        );
    }

    /// A test of veracruz using network communication using three sessions (one for program, one for data, and one for retrieval)
    #[actix_rt::test]
    async fn veracruz_phase2_linear_regression_three_clients() {
        let result = test_template::<LinearRegression>(
            LINEAR_REGRESSION_TRIPLE_POLICY,
            &vec![
                (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
                (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
                (RESULT_CLIENT_CERT, RESULT_CLIENT_KEY),
            ],
            (0, LINEAR_REGRESSION_WASM),
            &vec![(1, "input-0", LINEAR_REGRESSION_DATA)],
            &vec![1, 2],
        )
        .await;
        assert!(
            result.is_ok(),
            "veracruz_phase2_linear_regression_three_clients failed with error: {:?}",
            result
        );
    }

    /// A test of veracruz using network communication using four sessions
    /// (one for program, one for the first data, and one for the second data and retrieval.)
    #[actix_rt::test]
    async fn veracruz_phase2_intersection_set_sum_three_clients() {
        let result = test_template::<f64>(
            INTERSECTION_SET_SUM_TRIPLE_POLICY,
            &vec![
                (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
                (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
                (RESULT_CLIENT_CERT, RESULT_CLIENT_KEY),
            ],
            (0, CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
            &vec![
                (1, "input-0", INTERSECTION_SET_SUM_ADVERTISEMENT_DATA),
                (2, "input-1", INTERSECTION_SET_SUM_CUSTOMER_DATA),
            ],
            &vec![2],
        )
        .await;
        assert!(
            result.is_ok(),
            "veracruz_phase2_intersection_set_sum_two_clients failed with error: {:?}",
            result
        );
    }

    /// A test of veracruz using network communication using four sessions
    /// (one for program, one for the first data, and one for the second data and retrieval.)
    #[actix_rt::test]
    async fn veracruz_phase2_intersection_set_sum_two_clients_reversed_data_provision() {
        let result = test_template::<f64>(
            PERMUTED_INTERSECTION_SET_SUM_TRIPLE_POLICY,
            &vec![
                (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
                (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
                (RESULT_CLIENT_CERT, RESULT_CLIENT_KEY),
            ],
            (0, CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM),
            &vec![
                (2, "input-1", INTERSECTION_SET_SUM_CUSTOMER_DATA),
                (1, "input-0", INTERSECTION_SET_SUM_ADVERTISEMENT_DATA),
            ],
            &vec![2],
        )
        .await;
        assert!(result.is_ok(), "veracruz_phase2_intersection_set_sum_two_clients_reversed_data_provision failed with error: {:?}",result);
    }

    /// A test of veracruz using network communication using three sessions
    /// (one for program, one for the first data, and one for the second data and retrieval.)
    #[actix_rt::test]
    async fn veracruz_phase2_string_edit_distance_three_clients() {
        let result = test_template::<usize>(
            STRING_EDIT_DISTANCE_TRIPLE_POLICY,
            &vec![
                (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
                (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
                (RESULT_CLIENT_CERT, RESULT_CLIENT_KEY),
            ],
            (0, STRING_EDIT_DISTANCE_WASM),
            &vec![
                (1, "input-0", STRING_1_DATA),
                (2, "input-1", STRING_2_DATA),
            ],
            &vec![2],
        )
        .await;
        assert!(
            result.is_ok(),
            "veracruz_phase2_string_edit_distance_three_clients failed with error: {:?}",
            result
        );
    }

    /// A test of veracruz using network communication using four sessions
    /// (one for program, one for the first data, one for the second data, and one for retrieval.)
    #[actix_rt::test]
    async fn veracruz_phase3_string_edit_distance_four_clients() {
        let result = test_template::<usize>(
            STRING_EDIT_DISTANCE_QUADRUPLE_POLICY,
            &vec![
                (PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY),
                (DATA_CLIENT_CERT, DATA_CLIENT_KEY),
                (DATA_CLIENT_SECOND_CERT, DATA_CLIENT_SECOND_KEY),
                (RESULT_CLIENT_CERT, RESULT_CLIENT_KEY),
            ],
            (0, STRING_EDIT_DISTANCE_WASM),
            &vec![(1, "input-0", STRING_1_DATA), (2, "input-1", STRING_2_DATA)],
            &vec![3],
        )
        .await;
        assert!(
            result.is_ok(),
            "veracruz_phase3_string_edit_distance_four_clients failed with error: {:?}",
            result
        );
    }

    /// a test of veracruz using network communication using two parallel sessions
    /// (one for program, one for data sending and retrieving)
    #[actix_rt::test]
    async fn veracruz_phase4_linear_regression_two_clients_parallel() {
        let policy_json = std::fs::read_to_string(LINEAR_REGRESSION_PARALLEL_POLICY).unwrap();
        let policy = Policy::from_json(&policy_json).unwrap();

        setup(policy.proxy_attestation_server_url().clone());

        task::sleep(std::time::Duration::from_millis(5000)).await;
        let server_handle = server_tls_loop(LINEAR_REGRESSION_PARALLEL_POLICY);

        #[cfg(feature = "sgx")]
        let target_platform = Platform::SGX;
        #[cfg(feature = "tz")]
        let target_platform = Platform::TrustZone;
        #[cfg(feature = "nitro")]
        let target_platform = Platform::Nitro;
        #[cfg(feature = "icecap")]
        let target_platform = Platform::IceCap;

        let program_provider_handle = async {
            task::sleep(std::time::Duration::from_millis(10000)).await;
            info!("### program provider start.");
            let mut client =
                veracruz_client::VeracruzClient::new(PROGRAM_CLIENT_CERT, PROGRAM_CLIENT_KEY,
                                      &policy_json,
                                      &target_platform)?;
            let program_path = LINEAR_REGRESSION_WASM;
            let program_filename = Path::new(program_path).file_name().unwrap().to_str().unwrap();
            info!("### program provider read binary.");
            let program_data = read_binary_file(&program_path)?;
            info!("### program provider send binary.");
            client.send_program(program_filename,&program_data)?;
            info!("### program provider request shutdown.");
            client.request_shutdown()?;
            Ok::<(), VeracruzTestError>(())
        };
        let data_provider_handle = async {
            task::sleep(std::time::Duration::from_millis(15000)).await;
            info!("### data provider start.");
            let mut client =
                veracruz_client::VeracruzClient::new(DATA_CLIENT_CERT, DATA_CLIENT_KEY, &policy_json, &target_platform)?;

            let data_filename = LINEAR_REGRESSION_DATA;
            info!("### data provider read input.");
            let data = read_binary_file(&data_filename)?;
            info!("### data provider send input.");
            client.send_data("input-0",&data)?;
            let program_path = LINEAR_REGRESSION_WASM;
            let program_filename = Path::new(program_path).file_name().unwrap().to_str().unwrap();
            info!("### data provider read result.");
            client.get_results(program_filename)?;
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
    }

    async fn test_template<T: std::fmt::Debug + serde::de::DeserializeOwned>(
        // Policy files
        policy_path: &str,
        // List of client's certificates and private keys
        client_configs: &[(&str, &str)],
        // Program provider, index refering to the `client_configs` parameter, and program path
        (program_provider_index, program_path): (usize, &str),
        // Data providers, a list of indices refering to the `client_configs` parameter,
        // remote file name and data pathes.
        // The list determines the order of which data is sent out, from head to tail.
        // Note that a client might provision more than one packages
        data_providers: &[(usize, &str, &str)],
        // Result retriever, a list of indices refering to the `client_configs` parameter.
        result_retrievers: &[usize],
    ) -> Result<(), VeracruzTestError> {
        let policy_json = std::fs::read_to_string(policy_path)?;
        let policy = Policy::from_json(&policy_json)?;
        setup(policy.proxy_attestation_server_url().clone());
        info!("### Step 0. Read the policy file {}.", policy_path);

        // Wait the setup
        task::sleep(std::time::Duration::from_millis(5000)).await;

        let server_handle = server_tls_loop(policy_path);

        let clients_handle = async {
            // Wait for the enclave initialasation
            task::sleep(std::time::Duration::from_millis(10000)).await;

            info!("### Step 2. Set up all client sessions.");
            let mut clients = Vec::new();
            for (cert, key) in client_configs.iter() {
                #[cfg(feature = "sgx")]
                let target_platform = Platform::SGX;
                #[cfg(feature = "tz")]
                let target_platform = Platform::TrustZone;
                #[cfg(feature = "nitro")]
                let target_platform = Platform::Nitro;
                #[cfg(feature = "icecap")]
                let target_platform = Platform::IceCap;

                clients.push(veracruz_client::VeracruzClient::new(cert, key, &policy_json, &target_platform)?);
            }

            info!(
                "### Step 3. Client #{} provisions program {}.",
                program_provider_index, program_path
            );
            // provision program
            let program_provider_veracruz_client = clients
                .get_mut(program_provider_index)
                .ok_or(VeracruzTestError::ClientIndexError(program_provider_index))?;
            let program_data = read_binary_file(program_path)?;
            let program_name = Path::new(program_path).file_name().unwrap().to_str().unwrap();
            program_provider_veracruz_client.send_program(&program_name,&program_data)?;
            info!("### Step 4. Provision data.");
            // provosion data
            for (data_provider_index, remote_filename, data_filename) in data_providers.iter() {
                info!(
                    "            Client #{} provisions program {}.",
                    data_provider_index, data_filename
                );
                let data_provider_veracruz_client = clients
                    .get_mut(*data_provider_index)
                    .ok_or(VeracruzTestError::ClientIndexError(*data_provider_index))?;
                let data = read_binary_file(data_filename)?;
                data_provider_veracruz_client.send_data(remote_filename,&data)?;
            }

            info!("### Step 5. Retrieve result and gracefully shutdown the server.");
            // fetch result
            for result_retriever_index in result_retrievers {
                let result_retriever_veracruz_client = clients
                    .get_mut(*result_retriever_index)
                    .ok_or(VeracruzTestError::ClientIndexError(*result_retriever_index))?;
                let result = result_retriever_veracruz_client.get_results(program_name)?;
                let result: T = pinecone::from_bytes(&result)?;
                info!("            Result: {:?}", result);
            }

            for client_index in 0..client_configs.len() {
                clients
                    .get_mut(client_index)
                    .ok_or(VeracruzTestError::ClientIndexError(client_index))?
                    .request_shutdown()?;
                info!("            Client {} disconnects", client_index);
            }
            Ok::<(), VeracruzTestError>(())
        };
        info!("            Server and clients threads execute.");
        let _ = futures::try_join!(server_handle, clients_handle)?;
        info!("### Step 6. Server and clients threads join.");
        Ok(())
    }

    async fn server_tls_loop(policy_filename: &str) -> Result<(), VeracruzTestError> {
        veracruz_server::server::server(policy_filename)?.await?;
        Ok(())
    }
}
