//! Veracruz server build file.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root director for licensing
//! and copyright information.

use std::env;
use target_build_utils;

fn main() {
    {
        let target = target_build_utils::TargetInfo::new().expect("could not get target info");
        let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/work/sgxsdk".to_string());
        let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

        println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
        match is_sim.as_ref() {
            "SW" => println!("cargo:rustc-link-lib=dylib=sgx_urts_sim"),
            "HW" => {
                let target = target_build_utils::TargetInfo::new().unwrap();
                if target.target_arch() == "x86_64" {
                    println!("cargo:rustc-link-lib=dylib=sgx_urts");
                    println!("cargo:rustc-link-lib=dylib=sgx_tkey_exchange");
                    println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
                    println!("cargo:rustc-link-lib=dylib=sgx_ukey_exchange");
                }
            }
            _ => println!("cargo:rustc-link-lib=dylib=sgx_urts"), // Treat undefined as HW
        }
    }
}
