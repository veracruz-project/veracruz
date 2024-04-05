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
use log::info;
use std::{
    fs::{self, File, remove_dir_all, create_dir_all},
    io::{Write},
    path::{Path, PathBuf},
    process::Command
};
use policy_utils::principal::PrincipalPermission;
use crate::Execution;
#[cfg(feature = "std")]
use nix::sys::signal;

/// Path to the native module's manager sysroot on the kernel filesystem. Native
/// module directories are created under this directory.
const NATIVE_MODULE_MANAGER_SYSROOT: &str = "/tmp/nmm/";

/// Path to the native module sandboxer. This is the program that actually prepares
/// the sandbox environment and runs the native module in it.
const NATIVE_MODULE_MANAGER_SANDBOXER_PATH: &str = "/tmp/nmm/native-module-sandboxer";

/// Execution configuration file name. The input from the calling program is
/// written to this file, under the native module's directory, before running
/// the native module.
const EXECUTION_CONFIGURATION_FILE: &str = "execution_config";

/// Sandbox execution handler.
pub struct Sandbox {
    native_module_directory: PathBuf,
    execution_permissions: PrincipalPermission,
}

impl Execution for Sandbox {
    /// name of this execution.
    fn name(&self) -> &str {
        "Executing binary in sandbox."
    }

    /// Execute the native binary program at `program_path`.
    fn execute(&mut self, program_path: &Path) -> Result<()> {

        info!("Binary path {program_path:?}");
        // Inject execution configuration into the native module's directory
        let mut config_file = File::create(self.native_module_directory.join(EXECUTION_CONFIGURATION_FILE))?;

        info!("Binary configuration file {config_file:?}");
        config_file.write_all(&vec![])?;

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
            )?;
        }

        let execution_permissions = self.execution_permissions.iter().map(|(path, _permission)| {
            path.clone()
        }).collect();

        info!("Directories to mount: {execution_permissions:?}");

        let mount_mappings = build_mappings(&self.native_module_directory, execution_permissions)?;
        info!("Binary mounted mapping {mount_mappings}");

        let program_name = program_path.file_name().and_then(|os_str| os_str.to_str()).ok_or(anyhow!("Failed to extract program name from program path to a native binary."))?;
        let entry_point = self.native_module_directory.join(program_name);
        fs::copy(program_path, &entry_point)?;
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
                entry_point,
            ])
            .output()?;

        info!("Tear down...");
        self.teardown_fs()?;

        Ok(())
    }
}
 
impl Sandbox {
    /// Create a sandbox at the (sub-)directory `dir_name` 
    /// on the path `${NATIVE_MODULE_MANAGER_SYSROOT}`, i.e., `/tmp/nmm/`.
    pub(crate) fn new(execution_permissions: PrincipalPermission, dir_name: &str) -> Self {
        info!("Create a new sandbox {dir_name}");
        let native_module_directory = PathBuf::from(NATIVE_MODULE_MANAGER_SYSROOT).join(dir_name);

        info!("Create a new sandbox from binary {dir_name}, going to be mounted at {native_module_directory:?}.");
        let _ = create_dir_all(&native_module_directory);
        Self {
            native_module_directory,
            execution_permissions,
        }
    }

    fn teardown_fs(&self) -> Result<()> {
        remove_dir_all(self.native_module_directory.as_path())?;
        Ok(())
    }
}

impl Drop for Sandbox {
    /// Drop the native module manager.
    fn drop(&mut self) {
        let _ = self.teardown_fs();
    }
}

/// Build kernel-to-sandbox filesystem mappings palatable to the native
/// module sandboxer.
/// Takes a list of unprefixed paths, i.e. not including the path to the
/// native module's directory.
/// Returns the mappings as a string.
fn build_mappings(native_module_directory: &PathBuf, unprefixed_files: Vec<PathBuf>) -> Result<String> {

    info!("construct mappings from source: {unprefixed_files:?}");
    // Convert `path` in `unprefixed_files` into a string of format of 
    // `{target_path}=>{host_path}`, and then collect the result as a Vec, `mappings`.
    let mut mappings = unprefixed_files.into_iter().fold(Ok(Vec::new()), |acc:Result<Vec<String>>, path|{
        let mut acc = acc?;
        // Remove the prefix, either relative path or abusolute path.
        // e.g., `./foo` to `foo`, and `/foo/bar/` to `foo/bar/`.
        // The resulting string will be `join` with 
        // the new prefix `{native_module_directory}`.
        let target_path_directory = if path.has_root() {
            path.strip_prefix("/")?
        } else if path.is_relative() {
            path.strip_prefix("./")?
            
        } else { &path };
        let mut target_path = native_module_directory.join(&target_path_directory).to_str()
            .ok_or(anyhow!("Failed to convert native_module_directory to str"))?
            .to_string();
        let host_path = path.canonicalize()?;
        let host_path = host_path.to_str()
            .ok_or(anyhow!("Failed to convert native_module_directory to str"))?;

        // Convert `target_path` and `host_path` to 
        // a string `{target_path}=>{host_path}`.
        target_path.push_str("=>");
        target_path.push_str(host_path);
        acc.push( target_path );
        Ok(acc)
    })?;

    // Add the final `execution_config` mapping.
    let mut execution_config = native_module_directory
                 .join(EXECUTION_CONFIGURATION_FILE)
                 .to_str()
                 .ok_or(anyhow!("Failed to convert {} to str", EXECUTION_CONFIGURATION_FILE))?
                 .to_owned();
    execution_config.push_str("=>/");
    execution_config.push_str(EXECUTION_CONFIGURATION_FILE);

    mappings.push(execution_config);

    info!("sandbox mappings: {mappings:?}");
    
    // Convert the to the final string, where individual mapping is Concatenated by comma `,`.
    Ok(mappings.join(","))
}
