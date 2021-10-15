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

// NB: added to avoid a compile failure in Rust's futures library.
#![feature(proc_macro_hygiene)]

pub fn main() -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    // Policies
    const GET_RANDOM_POLICY: &'static str = "get_random_policy.json";
    const LINEAR_REGRESSION_DUAL_POLICY: &'static str = "dual_policy.json";
    const LINEAR_REGRESSION_TRIPLE_POLICY: &'static str = "triple_policy.json";
    const LINEAR_REGRESSION_PARALLEL_POLICY: &'static str = "dual_parallel_policy.json";
    const INTERSECTION_SET_SUM_TRIPLE_POLICY: &'static str =
        "triple_parties_two_data_sources_sum_policy.json";
    const PERMUTED_INTERSECTION_SET_SUM_TRIPLE_POLICY: &'static str =
        "permuted_triple_parties_two_data_sources_sum_policy.json";
    const STRING_EDIT_DISTANCE_TRIPLE_POLICY: &'static str =
        "triple_parties_two_data_sources_string_edit_distance_policy.json";
    const STRING_EDIT_DISTANCE_QUADRUPLE_POLICY: &'static str =
        "quadruple_policy.json";

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
    const INTERSECTION_SET_SUM_ADVERTISEMENT_DATA: &'static str = "intersection-advertisement-viewer.dat";
    const STRING_1_DATA: &'static str = "hello-world-1.dat";
    const STRING_2_DATA: &'static str = "hello-world-2.dat";

    use actix_rt::System;
    use async_std::task;
    use veracruz_client;
    use env_logger;
    use err_derive::Error;
    use log::info;
    use serde::Deserialize;
    use veracruz_server;
    use std::{env, io::Read, sync::Once, path::{Path, PathBuf}};
    use proxy_attestation_server;
    use veracruz_utils::policy::policy::Policy;

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
                let server = proxy_attestation_server::server::server(
                    proxy_attestation_server_url,
                    trust_path(CA_CERT).as_path(),
                    trust_path(CA_KEY).as_path(),
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
    #[cfg(not(feature = "icecap"))]
    #[actix_rt::test]
    async fn veracruz_phase1_get_random_one_client() {
        let result = test_template::<Vec<u8>>(
            policy_path(GET_RANDOM_POLICY).as_path(),
            &vec![(trust_path(CLIENT_CERT).as_path(), trust_path(CLIENT_KEY).as_path())],
            0, 
            program_path(RANDOM_SOURCE_WASM).as_path(),
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
            policy_path(LINEAR_REGRESSION_DUAL_POLICY).as_path(),
            &vec![
                (trust_path(PROGRAM_CLIENT_CERT).as_path(), trust_path(PROGRAM_CLIENT_KEY).as_path()),
                (trust_path(DATA_CLIENT_CERT).as_path(), trust_path(DATA_CLIENT_KEY).as_path()),
            ],
            0, program_path(LINEAR_REGRESSION_WASM).as_path(),
            &vec![(1, "input-0", data_path(LINEAR_REGRESSION_DATA).as_path())],
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
            policy_path(LINEAR_REGRESSION_TRIPLE_POLICY).as_path(),
            &vec![
                (trust_path(PROGRAM_CLIENT_CERT).as_path(), trust_path(PROGRAM_CLIENT_KEY).as_path()),
                (trust_path(DATA_CLIENT_CERT).as_path(), trust_path(DATA_CLIENT_KEY).as_path()),
                (trust_path(RESULT_CLIENT_CERT).as_path(), trust_path(RESULT_CLIENT_KEY).as_path()),
            ],
            0, program_path(LINEAR_REGRESSION_WASM).as_path(),
            &vec![(1, "input-0", data_path(LINEAR_REGRESSION_DATA).as_path())],
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
            policy_path(INTERSECTION_SET_SUM_TRIPLE_POLICY).as_path(),
            &vec![
                (trust_path(PROGRAM_CLIENT_CERT).as_path(), trust_path(PROGRAM_CLIENT_KEY).as_path()),
                (trust_path(DATA_CLIENT_CERT).as_path(), trust_path(DATA_CLIENT_KEY).as_path()),
                (trust_path(RESULT_CLIENT_CERT).as_path(), trust_path(RESULT_CLIENT_KEY).as_path()),
            ],
            0, program_path(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM).as_path(),
            &vec![
                (1, "input-0", data_path(INTERSECTION_SET_SUM_ADVERTISEMENT_DATA).as_path()),
                (2, "input-1", data_path(INTERSECTION_SET_SUM_CUSTOMER_DATA).as_path()),
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
            policy_path(PERMUTED_INTERSECTION_SET_SUM_TRIPLE_POLICY).as_path(),
            &vec![
                (trust_path(PROGRAM_CLIENT_CERT).as_path(), trust_path(PROGRAM_CLIENT_KEY).as_path()),
                (trust_path(DATA_CLIENT_CERT).as_path(), trust_path(DATA_CLIENT_KEY).as_path()),
                (trust_path(RESULT_CLIENT_CERT).as_path(), trust_path(RESULT_CLIENT_KEY).as_path()),
            ],
            0, program_path(CUSTOMER_ADS_INTERSECTION_SET_SUM_WASM).as_path(),
            &vec![
                (2, "input-1", data_path(INTERSECTION_SET_SUM_CUSTOMER_DATA).as_path()),
                (1, "input-0", data_path(INTERSECTION_SET_SUM_ADVERTISEMENT_DATA).as_path()),
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
            policy_path(STRING_EDIT_DISTANCE_TRIPLE_POLICY).as_path(),
            &vec![
                (trust_path(PROGRAM_CLIENT_CERT).as_path(), trust_path(PROGRAM_CLIENT_KEY).as_path()),
                (trust_path(DATA_CLIENT_CERT).as_path(), trust_path(DATA_CLIENT_KEY).as_path()),
                (trust_path(RESULT_CLIENT_CERT).as_path(), trust_path(RESULT_CLIENT_KEY).as_path()),
            ],
            0, program_path(STRING_EDIT_DISTANCE_WASM).as_path(),
            &vec![
                (1, "input-0", data_path(STRING_1_DATA).as_path()),
                (2, "input-1", data_path(STRING_2_DATA).as_path()),
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
            policy_path(STRING_EDIT_DISTANCE_QUADRUPLE_POLICY).as_path(),
            &vec![
                (trust_path(PROGRAM_CLIENT_CERT).as_path(), trust_path(PROGRAM_CLIENT_KEY).as_path()),
                (trust_path(DATA_CLIENT_CERT).as_path(), trust_path(DATA_CLIENT_KEY).as_path()),
                (trust_path(DATA_CLIENT_SECOND_CERT).as_path(), trust_path(DATA_CLIENT_SECOND_KEY).as_path()),
                (trust_path(RESULT_CLIENT_CERT).as_path(), trust_path(RESULT_CLIENT_KEY).as_path()),
            ],
            0, program_path(STRING_EDIT_DISTANCE_WASM).as_path(),
            &vec![(1, "input-0", data_path(STRING_1_DATA).as_path()), (2, "input-1", data_path(STRING_2_DATA).as_path())],
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
        let policy_json = read_policy(policy_path(LINEAR_REGRESSION_PARALLEL_POLICY).as_path()).unwrap();
        let policy = Policy::from_json(&policy_json).unwrap();

        setup(policy.proxy_attestation_server_url().clone());

        task::sleep(std::time::Duration::from_millis(5000)).await;
        let policy_file = policy_path(LINEAR_REGRESSION_PARALLEL_POLICY);
        let server_handle = server_tls_loop(policy_file.as_path());

        let program_provider_handle = async {
            task::sleep(std::time::Duration::from_millis(10000)).await;
            info!("### program provider start.");
            let mut client =
                veracruz_client::VeracruzClient::new(trust_path(PROGRAM_CLIENT_CERT).as_path(), trust_path(PROGRAM_CLIENT_KEY).as_path(),
                                      &policy_json)?;
            let prog_path = program_path(LINEAR_REGRESSION_WASM);
            let program_filename = prog_path.as_path().file_name().unwrap().to_str().unwrap();
            info!("### program provider read binary.");
            let program_data = read_binary_file(prog_path.as_path())?;
            info!("### program provider send binary.");
            client.send_program(program_filename, &program_data)?;
            info!("### program provider request shutdown.");
            client.request_shutdown()?;
            Ok::<(), VeracruzTestError>(())
        };
        let data_provider_handle = async {
            task::sleep(std::time::Duration::from_millis(15000)).await;
            info!("### data provider start.");
            let mut client =
                veracruz_client::VeracruzClient::new(trust_path(DATA_CLIENT_CERT).as_path(), trust_path(DATA_CLIENT_KEY).as_path(), &policy_json)?;

            let data_filename = data_path(LINEAR_REGRESSION_DATA);
            info!("### data provider read input.");
            let data = read_binary_file(&data_filename.as_path())?;
            info!("### data provider send input.");
            client.send_data("input-0",&data)?;
            let prog_path = program_path(LINEAR_REGRESSION_WASM);
            let program_filename = prog_path.as_path().file_name().unwrap().to_str().unwrap();
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
        policy_path: &Path,
        // List of client's certificates and private keys
        client_configs: &[(&Path, &Path)],
        // Program provider, index refering to the `client_configs` parameter, and program path
        program_provider_index: usize,
        program_path: &Path,
        // Data providers, a list of indices refering to the `client_configs` parameter,
        // remote file name and data pathes.
        // The list determines the order of which data is sent out, from head to tail.
        // Note that a client might provision more than one packages
        data_providers: &[(usize, &str, &Path)],
        // Result retriever, a list of indices refering to the `client_configs` parameter.
        result_retrievers: &[usize],
    ) -> Result<(), VeracruzTestError> {
        let policy_json = read_policy(policy_path)?;
        let policy = Policy::from_json(&policy_json)?;
        setup(policy.proxy_attestation_server_url().clone());
        info!("### Step 0. Read the policy file {}.", policy_path.to_string_lossy());

        // Wait the setup
        task::sleep(std::time::Duration::from_millis(5000)).await;

        let server_handle = server_tls_loop(policy_path);

        let clients_handle = async {
            // Wait for the enclave initialasation
            task::sleep(std::time::Duration::from_millis(10000)).await;

            info!("### Step 2. Set up all client sessions.");
            let mut clients = Vec::new();
            for (cert, key) in client_configs.iter() {
                clients.push(veracruz_client::VeracruzClient::new(cert, key, &policy_json)?);
            }

            info!(
                "### Step 3. Client #{} provisions program {}.",
                program_provider_index, program_path.to_string_lossy()
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
                    data_provider_index, data_filename.to_string_lossy()
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

    async fn server_tls_loop(policy_filename: &Path) -> Result<(), VeracruzTestError> {
        let policy_text = read_policy(policy_filename)?;
        veracruz_server::server::server(&policy_text)?.await?;
        Ok(())
    }

    fn read_policy(policy_filename: &Path) -> Result<String, VeracruzTestError> {
        let policy_text =
            std::fs::read_to_string(policy_filename)
                .expect(&format!("Cannot open file {}", policy_filename.to_string_lossy()));

        return Ok(policy_text);
    }
}
