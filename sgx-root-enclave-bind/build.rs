//! SGX root enclave build file.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root director for licensing
//! and copyright information.

extern crate bindgen;

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir_arg = format!("OUT_DIR={:}", out_dir);

    let final_dir_arg = {
        let out_dir_fields: Vec<&str> = out_dir.split("/").collect();
        let final_dir_fields: Vec<&str> = out_dir_fields[0..out_dir_fields.len()-3].to_vec();
        let final_dir = final_dir_fields.join("/");
        format!("FINAL_DIR={:}", final_dir)
    };

    let out_dir_link_search = format!("cargo:rustc-link-search={:}", out_dir);
    // link against the runtime manager non-secure library
    println!("cargo:rustc-link-search=../sgx-root-enclave/bin");
    println!("{:}", out_dir_link_search);
    println!("cargo:rustc-link-lib=static=sgx_root_enclave_u");
    println!("cargo:rustc-link-lib=dylib=sgx_urts");
    println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
    println!("cargo:rustc-link-lib=dylib=sgx_ukey_exchange");
    println!("cargo:rerun-if-changed=../sgx-root-enclave/sgx_root_enclave.edl");
    println!("cargo:rerun-if-changed=../sgx-root-enclave/src/lib.rs");
    println!("cargo:rerun-if-changed=../veracruz-utils/src/*.rs");

    let make_result = Command::new("make")
        .current_dir("../sgx-root-enclave")
        .args(&[out_dir_arg, final_dir_arg])
        .status()
        .unwrap();
    if !make_result.success() {
        panic!("sgx-root-enclave-bind: make sgx-root-enclave failed");
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-I/work/sgxsdk/include")
        .clang_arg("-I../third-party/rust-sgx-sdk/edl")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .rustified_enum("sgx_status_t")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings.rs file")
}
