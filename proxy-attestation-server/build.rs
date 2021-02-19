//! Veracruz proxy attestation server build script
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::process::Command;

fn main() {
    // TODO: Ideally, the following whould only be run for tests.
    // However, cargo doesn't currently support that.
    // https://github.com/rust-lang/cargo/issues/4001
    {
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rustc-link-search=/usr/lib/aarch64-linux-gnu");

        // Destroy, and then re-create and repopulate, the database
        Command::new("bash")
            .args(&["./populate-test-database.sh"])
            .output()
            .unwrap();
    }
}
