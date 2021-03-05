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

#[cfg(any(feature = "sgx", feature = "tz"))]
use std::env;
#[cfg(feature = "tz")]
use std::process::Command;
#[cfg(feature = "sgx")]
use target_build_utils;

fn main() {
    #[cfg(feature = "sgx")]
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
    #[cfg(feature = "tz")]
    {
        let out_dir = env::var("OUT_DIR").unwrap();
        let out_dir_arg = format!("OUT_DIR={:}", out_dir);

        let final_dir_arg = {
            let out_dir_fields: Vec<&str> = out_dir.split("/").collect();
            let final_dir_fields: Vec<&str> = out_dir_fields[0..out_dir_fields.len() - 3].to_vec();
            let final_dir = final_dir_fields.join("/");
            format!("FINAL_DIR={:}", final_dir)
        };

        let make_result = Command::new("make")
            .current_dir("../trustzone-root-enclave")
            .args(&[out_dir_arg.clone(), final_dir_arg.clone()])
            .status()
            .unwrap();
        if !make_result.success() {
            panic!("veracruz-server::build.rs: make sgx-root-enclave failed");
        }

        let make_result = Command::new("make")
            .current_dir("../runtime-manager")
            .args(&["trustzone".to_string(), out_dir_arg, final_dir_arg])
            .status()
            .unwrap();
        if !make_result.success() {
            panic!("veracruz-server::build.rs: make runtime-manager failed");
        }
    }
}
