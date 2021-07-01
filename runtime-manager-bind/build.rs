//! Bindings to the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

extern crate bindgen;

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir_arg = format!("OUT_DIR={:}", out_dir);

    let out_dir_fields: Vec<&str> = out_dir.split("/").collect();
    let final_dir_fields: Vec<&str> = out_dir_fields[0..out_dir_fields.len()-3].to_vec();
    let final_dir = final_dir_fields.join("/");
    let final_dir_arg = format!("FINAL_DIR={:}", final_dir);

    let out_dir_link_search = format!("cargo:rustc-link-search={:}", out_dir);
    // link against the runtime manager non-secure library
    println!("cargo:rustc-link-search=../runtime-manager/bin");
    println!("{:}", out_dir_link_search);
    println!("cargo:rustc-link-lib=static=runtime_manager_u");
    println!("cargo:rerun-if-changed=.");
    println!("cargo:rerun-if-changed=../runtime-manager/");
    println!("cargo:rerun-if-changed=../runtime-manager/Makefile");

    let make_result = Command::new("make")
        .arg("sgx")
        .current_dir("../runtime-manager")
        .args(&[out_dir_arg, final_dir_arg])
        .status()
        .unwrap();
    if !make_result.success() {
        panic!("runtime-manager-bind: build.rs failed to run make ../runtime-manager");
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-I/work/sgxsdk/include")
        .clang_arg("-I../third-party/rust-sgx-sdk/edl")
        .clang_arg("-I".to_string() + &out_dir)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings.rs file")
}
