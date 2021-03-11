//! Veracruz proxy attestation server build script
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "sgx")]
use std::process::Command;
#[cfg(feature = "sgx")]
use hex;
#[cfg(feature = "nitro")]
use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-search=/usr/lib/aarch64-linux-gnu");

    // grab hashes from the root enclaves
    #[cfg(feature = "sgx")]
    {
        println!("cargo:rerun-if-changed=../trustzone-root-enclave/css.bin");
        println!("cargo:rustc-env=SGX_FIRMWARE_VERSION=0.3.0");
        println!(
            "cargo:rustc-env=SGX_FIRMWARE_HASH={}",
            hex::encode(
                Command::new("dd")
                    .args(&[
                        "skip=960",
                        "count=32",
                        "if=../trustzone-root-enclave/css.bin",
                        "bs=1",
                        "status=none"])
                    .output()
                    .unwrap()
                    .stdout
            ),
        );
    }

    #[cfg(feature = "psa")]
    {
        println!("cargo:rustc-env=PSA_FIRMWARE_VERSION=0.3.0");
        println!(
            "cargo:rustc-env=PSA_FIRMWARE_HASH={}",
            "deadbeefdeadbeefdeadbeefdeadbeeff00dcafef00dcafef00dcafef00dcafe"
        );
    }

    #[cfg(feature = "nitro")]
    {
        println!("cargo:rerun-if-changed=../nitro-root-enclave/PCR0");
        println!("cargo:rustc-env=NITRO_FIRMWARE_VERSION=0.1.0");
        println!(
            "cargo:rustc-env=NITRO_FIRMWARE_HASH={}",
            fs::read("../nitro-root-enclave/PCR0")
                .unwrap()
                .stdout
        );
    }
}
