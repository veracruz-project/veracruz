//! Fuzz Initializing sinaloa sgx enclave
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

use veracruz_utils;
// use SGX to fuzz the functionality
use sinaloa::SinaloaSGX as SinaloaEnclave;
use veracruz_server::sinaloa::Sinaloa;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(policy) = veracruz_utils::VeracruzPolicy::new(s) {
            let enclave = SinaloaEnclave::new(&policy);
            assert!(enclave.is_ok());
        }
    }
});
