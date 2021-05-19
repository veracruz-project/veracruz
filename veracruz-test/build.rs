//! Veracruz test build script
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
    Command::new("bash")
        .args(&["./populate-test-database.sh"])
        .output()
        .unwrap();
}
