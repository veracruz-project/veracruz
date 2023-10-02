//! The Veracruz native module manager
//!
//! This module manages the execution of native modules. It supports the
//! execution of static, dynamic and provisioned native modules (cf.
//! `NativeModuleType` for more details).
//! For the dynamic and provisioned ones, the native module manager prepares a
//! sandbox environment before running them inside it. The execution environment
//! is torn down after computation as a security precaution.
//!
//! Native modules follow the specifications below:
//!  - A native module has a name, special file and entry point
//!  - A native module has the same access rights to the VFS as the WASM program
//!    calling it. Provisioned native modules have their access rights specified
//!    in the policy like a regular WASM program
//!  - The caller (WASM program or participant) must provide an execution
//!    configuration to the native module. For static and dynamic native
//!    modules, it is provided via the native module's special file on the VFS.
//!    For provisioned native modules, it is provided via the special
//!    `EXECUTION_CONFIGURATION_FILE` on the VFS.
//!    It is up to the caller and native module to determine how the data is
//!    encoded, however dynamic and provisioned native modules MUST read the
//!    data from `EXECUTION_CONFIGURATION_FILE`, a file copied into the sandbox
//!    environment by the native module manager. Static native modules, on the
//!    other hand, read the data via `try_parse()` (cf. the `StaticNativeModule`
//!    trait)
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::{anyhow, Result};
use crate::{
    native_modules::common::STATIC_NATIVE_MODULES
};
use log::info;
use policy_utils::principal::{NativeModule, NativeModuleType};
use std::{
    fs::{File, remove_dir_all},
    io::{Write},
    path::PathBuf,
    process::Command
};
#[cfg(feature = "std")]
use nix::sys::signal;

/// Path to the native module's manager sysroot on the kernel filesystem. Native
/// module directories are created under this directory.
const NATIVE_MODULE_MANAGER_SYSROOT: &str = "/tmp/nmm";

/// Path to the native module sandboxer. This is the program that actually prepares
/// the sandbox environment and runs the native module in it.
const NATIVE_MODULE_MANAGER_SANDBOXER_PATH: &str = "/tmp/nmm/native-module-sandboxer";

/// Execution configuration file name. The input from the calling program is
/// written to this file, under the native module's directory, before running
/// the native module.
const EXECUTION_CONFIGURATION_FILE: &str = "execution_config";

pub struct NativeModuleManager {
    /// Native module to execute.
    native_module: NativeModule,
    /// Native module directory. Gets mounted into the sandbox environment
    /// before the native module is executed.
    native_module_directory: PathBuf,
}

impl NativeModuleManager {
    pub fn new(native_module: NativeModule) -> Self {
        let native_module_directory = PathBuf::from(NATIVE_MODULE_MANAGER_SYSROOT).join(native_module.name());
        Self {
            native_module,
            native_module_directory,
        }
    }

    /// Build kernel-to-sandbox filesystem mappings palatable to the native
    /// module sandboxer.
    /// Takes a list of unprefixed paths, i.e. not including the path to the
    /// native module's directory.
    /// Returns the mappings as a string.
    fn build_mappings(&self, unprefixed_files: Vec<PathBuf>) -> Result<String> {
        let mut mappings = String::new();
        for f in unprefixed_files {
            let mapping = self
                .native_module_directory
                .join(&f)
                .to_str()
                .ok_or(anyhow!("Failed to convert native_module_directory to str"))?
                .to_owned()
                + "=>"
                + &f.to_str()
                .ok_or(anyhow!("Failed to convert {:?} to str",f))?
                .to_owned();
            mappings = mappings + &mapping + ",";
        }

        // Add the execution configuration file
        mappings = mappings
                   + &self.native_module_directory
                     .join(EXECUTION_CONFIGURATION_FILE)
                     .to_str()
                     .ok_or(anyhow!("Failed to convert {} to str", EXECUTION_CONFIGURATION_FILE))?
                     .to_owned()
                   + "=>/"
                   + EXECUTION_CONFIGURATION_FILE;
        Ok(mappings)
    }

    /// Delete native module's filesystem on the kernel filesystem.
    /// As of now, there is no point in doing this, since native modules have
    /// read and write access to the entire program's VFS, potentially making
    /// native module executions stateful. In the future, we might consider
    /// giving native modules access to only a subset of the program's VFS with
    /// limited permissions.
    fn teardown_fs(&self) -> Result<()> {
        remove_dir_all(self.native_module_directory.as_path())?;
        Ok(())
    }

    /// Run the native module. The input is passed by the WASM program via the
    /// native module's special file.
    pub fn execute(&mut self, input: Vec<u8>) -> Result<()> {
        if self.native_module.is_static() {
            // Look up native module in the static native modules table
            let mut nm = STATIC_NATIVE_MODULES
                .lock()
                .map_err(|_| anyhow!("Failed to lock STATIC_NATIVE_MODULES"))?;
            let native_module_name = self.native_module.name();
            let nm = nm
                .get_mut(native_module_name)
                .ok_or(anyhow!("cannot find native module: {}", native_module_name))?;
            if nm.try_parse(&input)? {
                nm.serve(&input)?;
            }
        } else {

            // Inject execution configuration into the native module's directory
            let mut file = File::create(self.native_module_directory.join(EXECUTION_CONFIGURATION_FILE))?;
            file.write_all(&input)?;

            // Enable SIGCHLD handling in order to synchronously execute the
            // sandboxer.
            // This is necessary as Veracruz-Server (Linux) disables SIGCHLD
            // handling, which is inherited by the runtime manager
            #[cfg(feature = "std")]
            unsafe {
                signal::sigaction(
                    signal::Signal::SIGCHLD,
                    &signal::SigAction::new(
                        signal::SigHandler::SigDfl,
                        signal::SaFlags::empty(),
                        signal::SigSet::empty(),
                    ),
                )
                .expect("sigaction failed");
            }

            // TODO change in the future
            let mount_mappings = self.build_mappings(vec!["/".into()])?;
            let entry_point = match self.native_module.r#type() {
                NativeModuleType::Dynamic { entry_point, .. } => entry_point.clone(),
                NativeModuleType::Provisioned { entry_point } => self.native_module_directory.join(entry_point),
                _ => panic!("should not happen"),
            };
            let entry_point = entry_point.to_str().ok_or(anyhow!("Failed to convert entry point to str"))?;

            // Make sure the entry point is executable.
            // This is a temporary workaround that only works on Linux.
            Command::new("chmod").args(["500", entry_point]).output()?;

            info!("Calling sandboxer...");
            Command::new(NATIVE_MODULE_MANAGER_SANDBOXER_PATH)
                .args([
                    "--sandbox2tool_resolve_and_add_libraries",
                    "--sandbox2tool_mount_tmp",
                    "--sandbox2tool_additional_bind_mounts",
                    &mount_mappings,
                    "--sandbox2tool_file_size_creation_limit",
                    "1048576",
                    "--sandbox2tool_need_networking",
                    entry_point,
                ])
                .output()?;

            self.teardown_fs()?;
        }

        Ok(())
    }
}

impl Drop for NativeModuleManager {
    /// Drop the native module manager.
    fn drop(&mut self) {
        let _ = self.teardown_fs();
    }
}
