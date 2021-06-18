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
    #[cfg(not(feature = "icecap"))]
    {
        let make_result = Command::new("make")
            .current_dir("../test-collateral")
            .status()
            .unwrap();
        if !make_result.success() {
            panic!("veracruz_test: make ../test-collateral failed.");
        }
        Command::new("bash")
            .args(&["./populate-test-database.sh"])
            .output()
            .unwrap();
    }
}
