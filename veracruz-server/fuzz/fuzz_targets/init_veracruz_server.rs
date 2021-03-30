//! Fuzz Initializing Veracruz server sgx enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root director for licensing
//! and copyright information.

#![no_main]
use libfuzzer_sys::fuzz_target;

use veracruz_utils::policy::policy::Policy;
// use SGX to fuzz the functionality
use veracruz_server::VeracruzServerSGX as VeracruzServerEnclave;
use veracruz_server::veracruz_server::VeracruzServer;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(policy) = Policy::new(s) {
            let enclave = VeracruzServerEnclave::new(&policy);
            assert!(enclave.is_ok());
        }
    }
});
