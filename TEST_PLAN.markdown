# Veracruz Test Plan

This document describes the various tests that the Veracruz project uses, and
their purpose.  If you add new features to the project then please ensure that
adequate tests are also contributed at the same time, and that this file is
updated with details of those tests and their purpose.  This is to ensure that
we do not duplicate work (e.g. when somebody notices an apparent test missing
in this file) and so that we know exactly what features of Veracruz we are
currently testing, and where we need to do more work.

Veracruz uses various different levels of tests.  These are:

## Module-level unit tests

Tests located within the functional crates are intended to act as unit tests
for those crates.  When contributing new Rust crates (or modules in any other
language) please ensure that adequate unit tests are included to test
functionality of the module in isolation.  For Rust code, this usually entails
writing a dedicated `tests` module that is invokable using the `cargo test`
command.

## Veracruz-server-test

(See the components Markdown file for a description of Veracruz's major
components and their roles.)

In the `veracruz-server-test` directory in the main Veracruz repository.  These
tests are intended to exercise the Veracruz server through a local functional
interface.

The tests are organized into phases, numbered 1--4. The phases allow easy
selection of a subset of the tests that can be executed in one go.

## Veracruz-test

In the `veracruz-test` directory in the main Veracruz repository.  These tests are
integration tests intended to exercise the entire stack, including the Veracuz
client, the Veracruz server, and the Runtime Manager.  The Veracruz client
interfaces with the Veracruz server using a (local) network connection.

The tests are organized again into phases, numbered 1--3, for the same reason that
Veracruz-server-tests are phased, as discussed above.

## Current test matrix

| Test Level    | Test Name                                                                      | Description | Policy File | Pi File | Data File(s) | Status |
|---------------|--------------------------------------------------------------------------------|-------------|-------------|---------|--------------|--------|
| veracruz-server-test  | test_phase1_init_destroy_enclave                                               | Load every valid policy file in the test-collateral/ and in test-collateral/invalid_policy, initialise an enclave. | test-collateral/*.json | n/a | n/a | written |
| veracruz-server-test  | test_phase1_new_session                                                        | Load policy file and check if a new session tls can be opened | test-collateral/*.json | n/a | n/a | written |
| veracruz-server-test  | test_phase1_enclave_self_signed_cert                                           | Load the Veracruz server and generate the self-signed certificate | test-collateral/*.json | n/a | n/a | written | 
| veracruz-server-test  | test_phase1_attestation_only                                                   | Test the attestation flow without sending any program or data into the Veracruz server | one_data_source_policy.json | n/a | n/a | written |
| veracruz-server-test  | test_phase1_fire_test_on_debug                                                 | Fire test. If the enclave debug message is correctly called | one_data_source_policy.json | n/a | n/a | written |
| veracruz-server-test  | test_phase2_single_session_with_invalid_client_certificate                     | Attempt to establish a client session with the Veracruz server with an invalid client certificate | one_data_source_policy.json | n/a | n/a | n/a |
| veracruz-server-test  | test_phase2_random_source_no_data_no_attestation                               | Integration test:<br>policy: PiProvider, DataProvider and ResultReader is the same party<br>computation: random-source<br>data sources: none | get_random_policy.json | random-source.wasm | n/a | written |
| veracruz-server-test  | test_phase2_random_source_no_program                                           | Attempt to fetch the result without program nor data | get_random_policy.json | n/a | n/a | written |
| veracruz-server-test  | test_phase2_incorrect_program_no_attestation                                   | Attempt to provision a wrong program | get_random_policy.json | string-edit-distance.wasm | n/a | written
| veracruz-server-test  | test_phase2_random_source_no_data_no_attestation_unauthorized_key              | Attempt to use an unauthorized key | get_random_policy.json | random-source.wasm | n/a | written 
| veracruz-server-test  | test_phase2_random_source_no_data_no_attestation_unauthorized_certificate      | Attempt to use an unauthorized certificate | get_random_policy.json | random-source.wasm | n/a | written
| veracruz-server-test  | test_phase2_random_source_no_data_no_attestation_unauthorized_client           | A unauthorized client attempt to connect the service | get_random_policy.json | random-source.wasm | n/a | written
| veracruz-server-test  | test_phase2_random_source_one_data_no_attestation                              | Attempt to provision more data than expected | get_random_policy.json | random-source.wasm | linear-regression.dat | written 
| veracruz-server-test  | test_phase2_linear_regression_single_data_no_attestation                       | Integration test:<br>policy: PiProvider, DataProvider and ResultReader is the same party<br>compuatation: linear regression<br>data sources: king-county-sqftliving-price | one_data_source_policy.json | linear-regression.wasm | king-county-sqftliving-price.dat | written | 
| veracruz-server-test  | test_phase2_linear_regression_no_data_no_attestation                           | Attempt to fetch result without data | one_data_source_policy.json | linear-regression.wasm | n/a | written | 
| veracruz-server-test  | test_phase2_intersection_sum_reversed_data_provisioning_two_data_no_attestation| A standard two data source scenario, where the data provisioned in the reversed order (client 1, then client 2) | two_data_source_intersection_set_policy.json | intersection-set-sum.wasm | customer.dat<br>advertisement-viewer.dat | written |
| veracruz-server-test  | test_phase2_string_edit_distance_two_data_no_attestation                       | Integration test:<br>policy: PiProvider, DataProvider and ResultReader is the same party | two_data_source_string_edit_distance_policy.json | string-edit-distance.wasm | lorum-ipsum-25-paras.dat<br>hello-world.dat | written |
| veracruz-server-test  | test_phase3_linear_regression_one_data_with_attestation                        | one_data_source_policy.json | linear-regression.wasm | king-county-sqftliving-price.dat | written |
| veracruz-server-test  | test_phase3_private_set_intersection_two_data_with_attestation                 | two_data_source_private_set_intersection_policy.json | private-set-intersection.wasm | private-set-1.dat<br>private-set-2.dat| written |
| veracruz-server-test  | test_phase4_number_stream_accumulation_one_data_two_stream_with_attestation    | Integration test: sum of an initial f64 number and two stream of f64 numbers | number-stream-accumulation.json | private-set-intersection.wasm | number-stream-init.dat<br>number-stream-1.dat<br>number-stream-2.dat | written |
| veracruz-server-test  | test_phase4_number_stream_accumulation_one_data_one_stream_with_attestation    | Attempt to fetch result without enough stream data | number-stream-accumulation.json | private-set-intersection.wasm | number-stream-init.dat<br>number-stream-1.dat | written |
| veracruz-server-test  | test_phase4_number_stream_accumulation_no_data_two_stream_with_attestation     | Attempt to provision stream data in the state of loading static data | number-stream-accumulation.json | private-set-intersection.wasm | number-stream-1.dat<br>number-stream-2.dat | written |
| veracruz-server-test  | test_phase4_number_stream_accumulation_no_data_three_stream_with_attestation   | Attempt to provision more stream data | number-stream-accumulation.json | private-set-intersection.wasm | number-stream-init.dat<br>number-stream-1.dat<br>number-stream-2.dat | written |
| veracruz-server-test  | test_performance_idash2017_with_attestation                                    | A performance measure on logistic regression | idash2017_logistic_regression_policy.json | idash2017.wasm | sdk/datasets/idash2017/\* |ignored - performance|
| veracruz-server-test  | test_performance_macd_with_attestation                                         | A performance measure on MACD algorithm, computing a few rounds of weighted average against a windows size and comparing the difference between adjacent values | moving_average_convergence_divergence.json | macd.wasm | ../sdk/datasets/macd/\* | ignored - performance |
| veracruz-server-test  | test_performance_set_intersection_sum_with_attestation                         | A performance measure on set intersection and then sum of intersection result | private_set_intersection_sum.json | private-set-intersection-sum.wasm | ../sdk/datasets/set_inter_sum/\* | written |
| veracruz-server-test  | test_multiple_keys                                                             | The issue was that the key storage in Mbed Crypto was being exhausted in proxy attestation server | moving_average_convergence_divergence.json | macd.wasm | ../sdk/datasets/macd/\* | ignored - performance | 
| veracruz-test |veracruz_phase1_get_random_one_client                                           | A test of veracruz using network communication using a single session | get_random_policy.json |random-source.wasm | || written |
| veracruz-test | veracruz_phase1_linear_regression_two_clients                                  | A test of veracruz using network communication using two sessions (one for program and one for data) | dual_policy.json | linear-regression.wasm | king-county-sqftliving-price.dat | | written |
| veracruz-test | veracruz_phase2_linear_regression_three_clients                                | A test of veracruz using network communication using three sessions (one for program, one for data, and one for retrieval) | triple_policy.json | linear-regression.wasm | king-county-sqftliving-price.dat| written |
| veracruz-test | veracruz_phase2_intersection_set_sum_three_clients                             | A test of veracruz using network communication using four sessions (one for program, one for the first data, and one for the second data and retrieval.) | triple_parties_two_data_sources_sum_policy.json | intersection-set-sum.wasm |advertisement-viewer.dat<cr>customer.dat | written |
| veracruz-test | veracruz_phase2_intersection_set_sum_two_clients_reversed_data_provision       | A test of veracruz using network communication using four sessions (one for program, one for the first data, and one for the second data and retrieval.) | triple_parties_two_data_sources_sum_policy.json |intersection-set-sum.wasm | customer.dat<br>advertisement-viewer.dat | written |
| veracruz-test | veracruz_phase2_string_edit_distance_three_clients                             | A test of veracruz using network communication using three sessions (one for program, one for the first data, and one for the second data and retrieval.) | triple_parties_two_data_sources_string_edit_distance_policy.json | string-edit-distance.wasm |lorum-ipsum-25-paras.dat<cr>hello-world.dat | written |
| veracruz-test | veracruz_phase3_string_edit_distance_four_clients                              | A test of veracruz using network communication using four sessions (one for program, one for the first data, one for the second data, and one for retrieval.) | quadruple_policy.json |string-edit-distance.wasm | lorum-ipsum-25-paras.dat<cr>hello-world.dat | written |
| veracruz-test | veracruz_phase4_linear_regression_two_clients_parallel                         | a test of veracruz using network communication using two parallel sessions (one for program, one for data sending and retrieving) | dual_policy.json | linear-regression.wasm | king-county-sqftliving-price.dat | written |
| veracruz-client        | test_internal_read_all_bytes_in_file_succ                                     | Test the VeracruzClient private function read_all_bytes_in_file with a valid file | n/a                         | n/a | n/a | written |
| veracruz-client        |test_internal_read_all_bytes_in_file_invalid_file                              | Test the VeracruzClient private function read_all_bytes_in_file with an invalid file | n/a                         | n/a | n/a | written |
| veracruz-client        | test_internal_read_all_bytes_in_file_invalid_path                             | Test the VeracruzClient private function read_all_bytes_in_file with an invalid path | n/a                         | n/a | n/a | written |
| veracruz-client        | test_internal_read_cert_succ                                                  | Test the VeracruzClient private function read_cert with a valid certificate file | n/a                         | n/a | n/a | written |
| veracruz-client        | test_internal_read_cert_invalid_certificate                                   | Test the VeracruzClient private function read_cert with an invalid certificate file (in this case, a key file) | n/a                         | n/a | n/a | written |
| veracruz-client        | test_internal_read_private_key_succ                                           | Test the VeracruzClient private function read_private_key with a valid private key file | n/a                         | n/a | n/a | written |
| veracruz-client        | test_internal_read_cert_invalid_private_key                                   | Test the VeracruzClient private function read_private_key with an invalid private key file (in this case, a certificate file) | n/a                         | n/a | n/a | written |
| veracruz-client        | test_set_up_mock_object_for_attestation_handler                               | Test the VeracruzClient test infrastructure for setting un a mock attestation server (sort of a meta-test, I suppose?) | one_data_source_policy.json | n/a | n/a | written |
| veracruz-client        | test_internal_init_self_signed_cert_client_config_succ                        | | one_data_source_policy.json | n/a | n/a | written |
| veracruz-client        | test_internal_init_self_signed_cert_client_config_invalid_ciphersuite         | | one_data_source_policy.json | n/a | n/a | written |
| veracruz-client        | test_veracruz_client_new_succ                                                         | Test the VeracruzClient new function with various valid policy files| ../test-collateral/\*.json   | n/a | n/a | written |
| veracruz-client | test_veracruz_client_new_fail                                                                | This function tests loading invalid policy.<br>Invalid or out-of-time certificate, and invalid or out-of-time enclave cert-time. | ../test-collateral/invalid_policy/\*.json | n/a | n/a | written |
| veracruz-client        | test_veracruz_client_new_unmatched_client_certificate                                 | Test VeracruzClient new function with mismatched client certificate and client key | one_data_source_policy.json | n/a | n/a | written |
| veracruz-client        | test_veracruz_client_new_unmatched_client_key                                         | Test VeracruzClient new function with mismatched client certificate and client key | one_data_source_policy.json | n/a | n/a | written |
| veracruz-client        | test_veracruz_client_new_invalid_enclave_name                                         | Test VeracruzClient new when provided with an invalid URL for the Veracruz server | one_data_source_policy.json | n/a | n/a | written |
| veracruz-client        | veracruz_client_policy_violations                                                     | Test VeracruzClient's policy enforcement by setting up new VeracruzClient instances, and then calling them using invalid client credentials for the policy | | n/a | n/a | not written |
| veracruz-client        | veracruz_client_session                                                               | Test VeracruzClient's ability to send and receive data | one_data_source_policy.json | n/a | n/a | ignored - need to rewrite to the new interfaces |
| proxy-attestation-server | test_psa_attestation                                                | Test the proxy attestation server's PSA Atttestation flow | n/a | n/a | n/a | written |
