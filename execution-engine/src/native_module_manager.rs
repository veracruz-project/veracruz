//! The Veracruz native module manager
//!
//! This module prepares a sandbox environment for each native module, before running them inside it.
//! The execution environment is torn down after computation as a security precaution.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::fs::{FileSystem, FileSystemResult};
//use libc::{c_int, c_void};
use policy_utils::principal::NativeModule;
use std::fs::{create_dir, create_dir_all, File, remove_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use wasi_types::ErrNo;

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
    /// Native module's view of the VFS. This is used to copy files from the VFS
    /// to the kernel filesystem.
    native_module_filesystem: FileSystem,
    /// Native module directory. Gets mounted into the sandbox environment
    /// before the native module is executed.
    native_module_directory: PathBuf,
}

impl NativeModuleManager {
    pub fn new(native_module: NativeModule, native_module_filesystem: FileSystem) -> Self
    {
        let native_module_directory = PathBuf::from(NATIVE_MODULE_MANAGER_SYSROOT).join(native_module.name());
        Self {
            native_module,
            native_module_filesystem,
            native_module_directory,
        }
    }

    /// Prepare native module's filesystem by copying to the kernel filesystem
    /// all the part of the VFS visible to the native module.
    /// To be useful, this function must be called after provisioning files to
    /// the VFS, and maybe even after the WASM program invokes the native module.
    pub fn prepare_filesystem(&mut self) -> FileSystemResult<()> {
        create_dir(self.native_module_directory.as_path()).map_err(|_| ErrNo::Access)?;

        let visible_files_and_dirs = self.native_module_filesystem.read_all_files_and_dirs_by_absolute_path(Path::new("/"))?;
        for (path, buffer) in visible_files_and_dirs {
            let path = self.native_module_directory.join(path);

            // Create parent directories
            let parent_path = path.parent().ok_or(ErrNo::NoEnt)?;
            create_dir_all(parent_path)?;

            match buffer {
                Some(b) => {
                    let mut file = File::create(path)?;
                    file.write_all(&b)?;
                },
                None => create_dir(path)?
            }
        }
        Ok(())
    }

    /// Delete native module's filesystem on the kernel filesystem.
    pub fn teardown_filesystem(&self) -> FileSystemResult<()>
    {
        remove_dir_all(self.native_module_directory.as_path())?;
        Ok(())
    }

    /// Run the native module. The input is passed by the WASM program via the
    /// native module's special file.
    pub fn execute(&mut self, input: Vec<u8>) -> FileSystemResult<()> {
        self.prepare_filesystem()?;

        // Inject input (execution configuration) into the native module's directory
        let mut file = File::create(self.native_module_directory.join(EXECUTION_CONFIGURATION_FILE))?;
        file.write_all(&input)?;

        // Call sandboxer
        let mount_mapping = self.native_module_directory.to_str().ok_or(ErrNo::Inval)?.to_owned() + "=>/";
        let child = Command::new(NATIVE_MODULE_MANAGER_SANDBOXER_PATH)
            .args([
                "--sandbox2tool_resolve_and_add_libraries",
                "--sandbox2tool_additional_bind_mounts",
                &mount_mapping,
                &self.native_module.entry_point_path().to_str().ok_or(ErrNo::Inval)?.to_owned(),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to spawn child process");

        let output = child.wait_with_output().expect("Failed to read stdout");
        println!("<<output: {:?}", &output.stdout);

        Ok(())
    }
}

impl Drop for NativeModuleManager {
    /// Drop the native module manager.
    fn drop(&mut self) {
        let _ = self.teardown_filesystem();
    }
}
