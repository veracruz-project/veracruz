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
    let source_dir_var = &env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let source_dir = Path::new(&source_dir_var);
    let out_dir_var = &env::var_os("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_var);
    let linux_dir = out_dir.join("linux");
    if !linux_dir.is_dir() {
        let git_status = Command::new("git")
            .current_dir(out_dir)
            .args(&["clone", "https://github.com/AMDESE/linux.git"])
            .status()
            .unwrap();
        if !git_status.success() {
            panic!("Failed to clone linux source");
        }
        let git_status = Command::new("git")
            .current_dir(out_dir.join("linux"))
            .args(&["checkout", "6e7765cb477a9753670d4351d14de93f1e9dbbd4"])
            .status()
            .unwrap();
        if !git_status.success() {
            panic!("Failed to checkout commit");
        }
    }

    let make_status = Command::new("make")
        .current_dir(&linux_dir)
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
            .args(&["clone", "https://github.com/AMDESE/sev-guest.git",])
            .status()
            .unwrap();
        if !git_status.success() {
            panic!("Failed to clone sev-guest project");
        }
        let git_status = Command::new("git")
            .current_dir(out_dir.join("sev-guest"))
            .args(&["checkout", "62317d7de4d79d4ca887b357dddf072082b0b078",])
            .status()
            .unwrap();
        if !git_status.success() {
            panic!("Failed to clone sev-guest project");
        }

        let patch_filename = source_dir.join("get-report.patch");
        let git_patch_status = Command::new("git")
            .current_dir(&sev_guest_dir)
            .args(&["apply", &patch_filename.as_os_str().to_str().unwrap()])
            .status()
            .unwrap();
        if !git_patch_status.success() {
            panic!("Failed to patch sev-guest project");
        }
    }

    let veracruz_mk_filename = source_dir.join("veracruz.mk");

    let mut full_string: String = "LINUX_INCLUDE=".to_string();
    full_string.push_str(linux_dir.as_os_str().to_str().unwrap());
    full_string.push_str("/usr/include");
    let linux_include = full_string.as_str();

    let make_status = Command::new("make")
        .current_dir(&sev_guest_dir)
        .args(&["-f", &veracruz_mk_filename.as_os_str().to_str().unwrap(), &linux_include])
        .status()
        .unwrap();
    if !make_status.success() {
        panic!("Failed to build sev-guest");
    }

    println!("cargo:rustc-link-lib=static=sev-guest-get-report");
    println!("cargo:rustc-link-search={:}", sev_guest_dir.display());
}