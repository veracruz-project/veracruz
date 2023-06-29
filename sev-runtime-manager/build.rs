//! SEV Runtime Manager build script
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::{
    env,
    path::Path,
    process::Command
};

fn main() {
    let out_dir_var = &env::var_os("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_var);
    let linux_dir = out_dir.join("linux");
    if !linux_dir.is_dir() {
        let git_status = Command::new("git")
            .current_dir(out_dir)
            .args(&["clone", "https://github.com/AMDESE/linux.git", "--depth", "1"])
            .status()
            .unwrap();
        if !git_status.success() {
            panic!("Failed to clone linux source");
        }
    }

    let make_status = Command::new("make")
        .current_dir(linux_dir)
        .args(&["headers"])
        .status()
        .unwrap();
    if !make_status.success() {
        panic!("Failed to build linux headers");
    }

    let sev_guest_dir = out_dir.join("sev-guest");
    if !sev_guest_dir.is_dir() {
        let git_status = Command::new("git")
            .current_dir(out_dir)
            .args(&["clone", "--single-branch", "-b", "main", "https://github.com/AMDESE/sev-guest.git",])
            .status()
            .unwrap();
        if !git_status.success() {
            panic!("Failed to clone sev-guest project");
        }
        let git_patch_status = Command::new("git")
            .current_dir(&sev_guest_dir)
            .args(&["apply", "./get-report.patch"])
            .status()
            .unwrap();
        if !git_patch_status.success() {
            panic!("Failed to patch sev-guest project");
        }
    }

    let make_status = Command::new("make")
        .current_dir(sev_guest_dir)
        .args(&["-f", "./veracruz.mk", "LINUX_INCLUDE=../linux/usr/include"])
        .status()
        .unwrap();
    if !make_status.success() {
        panic!("Failed to build sev-guest");
    }

    println!("cargo:rustc-link-lib=static=sev-guest-get-report");
    println!("cargo:rustc-link-search=./sev-guest");
}