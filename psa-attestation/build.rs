//! PSA Attestation library build script
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
extern crate target_build_utils;

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let cc = {
        cfg_if::cfg_if! {
            if #[cfg(feature = "tz")] {
                "/work/rust-optee-trustzone-sdk/optee/toolchains/aarch64/bin/aarch64-linux-gnu-gcc".to_string()
            } else if #[cfg(feature = "sgx")] {
                "gcc".to_string()
            } else if #[cfg(feature = "nitro")] {
                "musl-gcc".to_string()
            } else {
                env::var("CC").unwrap()
            }
        }
    };

    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir = env::var("OUT_DIR").unwrap();

    let outdir_arg = format!("OUT_DIR={:}", target_dir);

    // make the qcbor library
    let qcbor_dir = format!("{:}/lib/QCBOR", project_dir);
    let make_status = Command::new("make")
        .env("CC", &cc)
        .current_dir(qcbor_dir.clone())
        .args(&["all", outdir_arg.as_str()])
        .status()
        .unwrap();
    if !make_status.success() {
        panic!("QCBOR failed to build");
    }

    // make the mbed crypto library
    let mbed_crypto_dir = format!("{:}/lib/mbed-crypto", project_dir);
    let make_status = Command::new("make")
        .env("CC", &cc)
        .current_dir(mbed_crypto_dir.clone())
        .args(&["-j8", "all", outdir_arg.as_str()])
        .status()
        .unwrap();
    if !make_status.success() {
        panic!("mbedtls failed to build");
    }
    // fun fact: mbedtls/mbed-crytpo is already part of the optee code. So
    // on an optee build, we end up with symbol collisions.
    // However, it does not appear to contain the PSA Crypto symbols.
    // Thus, we sorta just need to have both copies right now.
    // The following renames the colliding symbols, sorta just brushing the
    // problem under the rug (until it comes back to bite me later, which it
    // it will)
    #[cfg(feature="tz")]
    let rename_status = Command::new("/work/rust-optee-trustzone-sdk/optee-qemuv8-3.7.0/toolchains/aarch64/bin/aarch64-linux-gnu-objcopy")
        .current_dir(target_dir.clone())
        .args(&["--redefine-syms", &format!("{}/redefined_symbols",project_dir), "./libmbedcrypto.a"])
        .status()
        .unwrap();
    #[cfg(feature = "tz")]
    if !rename_status.success() {
        panic!("rename of mbed-crypto symbols failed");
    }

    let t_cose_dir = format!("{:}/lib/t_cose", project_dir);
    let make_status = Command::new("make")
        .env("CC", &cc)
        .args(&["-f", "Makefile.psa", "all", outdir_arg.as_str()])
        .current_dir(t_cose_dir.clone())
        .status()
        .unwrap();
    if !make_status.success() {
        panic!("t_cose failed to build");
    }

    // Build the psa_attestation library
    let c_src_dir = format!("{:}/c_src/", project_dir);
    let make_status = Command::new("make")
        .env("CC", &cc)
        .current_dir(c_src_dir.clone())
        .args(&["all", outdir_arg.as_str()])
        .status()
        .unwrap();
    if !make_status.success() {
        panic!("psa_attestation C library failed to build");
    }

    println!("cargo:rustc-link-lib=static=psa_attestation");
    println!("cargo:rustc-link-search={:}", target_dir);
    println!("cargo:rustc-link-lib=static=qcbor");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
    println!("cargo:rustc-link-lib=static=t_cose");

    // Tell cargo to invalidate the build crate whenever the wrapper changes
    //println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // need to set ctypes_prefix to libc instead of std
        // https://github.com/rust-lang/rust-bindgen/issues/628
        .ctypes_prefix("libc")
        .clang_arg("-Ilib/t_cose/inc/")
        .clang_arg("-Ilib/QCBOR/inc/")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
