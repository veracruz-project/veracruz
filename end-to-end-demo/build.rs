//! End-to-end demo build script.
//!
//! This calls the `populate-test-database.sh` shell script in the
//! end-to-end demo directory, which populates the Veracruz Proxy
//! Attestation Service database with some initial measurements.
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

/// Entry point, which just invokes the `populate-test-database.sh`
/// shell script before exiting.
fn main() {
    Command::new("bash")
        .args(&["./populate-test-database.sh"])
        .output()
        .unwrap();
}
