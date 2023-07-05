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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::{
    fs::{strip_root_slash_path, strip_root_slash_str, FileSystem, FileSystemResult},
    native_modules::common::STATIC_NATIVE_MODULES,
};
use log::info;
#[cfg(feature = "std")]
use nix::sys::signal;
use policy_utils::principal::{NativeModule, NativeModuleType};
use std::{
    fs::{create_dir, create_dir_all, read_dir, remove_dir_all, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};
use wasi_types::{ErrNo, FdFlags, LookupFlags, OpenFlags};

/// Path to the native module's manager sysroot on the kernel filesystem. Native
/// module directories are created under this directory.
pub const NATIVE_MODULE_MANAGER_SYSROOT: &str = "/tmp/nmm";

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
    native_module_vfs: FileSystem,
    /// Native module directory. Gets mounted into the sandbox environment
    /// before the native module is executed.
    native_module_directory: PathBuf,
}

impl NativeModuleManager {
    pub fn new(native_module: NativeModule, native_module_vfs: FileSystem) -> Self {
        let native_module_directory = PathBuf::from(NATIVE_MODULE_MANAGER_SYSROOT)
            .join(strip_root_slash_str(native_module.name()));
        Self {
            native_module,
            native_module_vfs,
            native_module_directory,
        }
    }

    /// Build kernel-to-sandbox filesystem mappings palatable to the native
    /// module sandboxer.
    /// Takes a list of unprefixed paths, i.e. not including the path to the
    /// native module's directory.
    /// Returns the mappings as a string.
    fn build_mappings(&self, unprefixed_files: Vec<PathBuf>) -> FileSystemResult<String> {
        let mut mappings = String::new();
        for f in unprefixed_files {
            let mapping = self
                .native_module_directory
                .join(strip_root_slash_path(&f))
                .to_str()
                .ok_or(ErrNo::Inval)?
                .to_owned()
                + "=>"
                + &f.to_str().ok_or(ErrNo::Inval)?.to_owned();
            mappings = mappings + &mapping + ",";
        }

        // Add the execution configuration file
        mappings = mappings
            + &self
                .native_module_directory
                .join(strip_root_slash_str(EXECUTION_CONFIGURATION_FILE))
                .to_str()
                .ok_or(ErrNo::Inval)?
                .to_owned()
            + "=>/"
            + EXECUTION_CONFIGURATION_FILE;
        Ok(mappings)
    }

    /// Prepare native module's filesystem by copying to the kernel filesystem
    /// all the part of the VFS visible to the native module.
    /// Returns a list of top-level files, i.e. files immediately under the
    /// root, that should be copied to the kernel filesystem.
    /// Fails if creating a new file or directory or writing to a file fails.
    /// To be useful, this function must be called after provisioning files to
    /// the VFS, and maybe even after the WASM program invokes the native module.
    fn prepare_fs(&mut self) -> FileSystemResult<Vec<PathBuf>> {
        remove_dir_all(self.native_module_directory.as_path()).map_err(|_| ErrNo::Access)?;
        create_dir_all(self.native_module_directory.as_path()).map_err(|_| ErrNo::Access)?;
        let (visible_files_and_dirs, top_level_files) = self
            .native_module_vfs
            .read_all_files_and_dirs_by_absolute_path("/")?;
        for (path, buffer) in visible_files_and_dirs {
            let path = self
                .native_module_directory
                .join(strip_root_slash_path(&path));

            // Create parent directories
            let parent_path = path.parent().ok_or(ErrNo::NoEnt)?;
            create_dir_all(parent_path)?;

            match buffer {
                Some(b) => {
                    let mut file = File::create(&path)?;
                    file.write_all(&b)?;
                }
                None => create_dir(path)?,
            }
        }

        // Make sure all top-level files exist on the kernel filesystem to avoid
        // potential mount errors later on.
        // This is a workaround. Ideally, only files accessible to the principal
        // should be mounted, however these can't be easily identified.
        // Let's assume every top-level file is a directory. We don't care if
        // this results in errors later, since the native module is not supposed
        // to access these files
        for f in &top_level_files {
            let path = self.native_module_directory.join(strip_root_slash_path(&f));
            let _ = create_dir(path);
        }

        Ok(top_level_files)
    }

    /// Recursively copy a `path` under the native module's directory to the
    /// VFS.
    /// Takes an unprefixed path, i.e. not including the path to the native
    /// module's  directory.
    /// Access errors are ignored.
    /// This function should be called after the native module's execution to
    /// reflect the side effects of execution onto the VFS.
    fn copy_fs_to_vfs(&mut self, path_unprefixed: &Path) -> FileSystemResult<()> {
        let path_prefixed = self
            .native_module_directory
            .join(strip_root_slash_path(&path_unprefixed));
        if path_prefixed.is_dir() {
            for entry in read_dir(path_prefixed)? {
                let entry = entry?;
                let path_prefixed = entry.path();
                let path_unprefixed = path_prefixed
                    .strip_prefix(&self.native_module_directory)
                    .map_err(|_| ErrNo::Access)?;

                // Ignore execution configuration file
                if path_unprefixed == PathBuf::from(EXECUTION_CONFIGURATION_FILE) {
                    continue;
                }

                let path_unprefixed = PathBuf::from("/").join(path_unprefixed);
                if path_prefixed.is_dir() {
                    // Create directory on the VFS with `path_open()`
                    let prestat = self.native_module_vfs.find_prestat(&path_unprefixed);
                    if prestat.is_ok() {
                        let (fd, file_name) = prestat?;
                        self.native_module_vfs.path_open(
                            fd,
                            LookupFlags::empty(),
                            file_name,
                            OpenFlags::CREATE,
                            FileSystem::DEFAULT_RIGHTS,
                            FileSystem::DEFAULT_RIGHTS,
                            FdFlags::empty(),
                        )?;
                        self.copy_fs_to_vfs(&path_unprefixed)?;
                    }
                } else {
                    // Read file on the kernel fileystem by chunks of 1MiB
                    let mut f = File::open(&path_prefixed)?;
                    let mut buf: [u8; 1048576] = [0; 1048576];

                    // Copy file to the VFS. First truncate the VFS file then
                    // append to it. If the principal doesn't have write access,
                    // just ignore it
                    if self
                        .native_module_vfs
                        .write_file_by_absolute_path(&path_unprefixed, vec![], false)
                        .is_ok()
                    {
                        loop {
                            let n = f.read(&mut buf)?;
                            if n == 0 {
                                break;
                            }
                            self.native_module_vfs.write_file_by_absolute_path(
                                &path_unprefixed,
                                buf[..n].to_vec(),
                                true,
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Delete native module's filesystem on the kernel filesystem.
    /// As of now, there is no point in doing this, since native modules have
    /// read and write access to the entire program's VFS, potentially making
    /// native module executions stateful. In the future, we might consider
    /// giving native modules access to only a subset of the program's VFS with
    /// limited permissions.
    fn teardown_fs(&self) -> FileSystemResult<()> {
        remove_dir_all(self.native_module_directory.as_path())?;
        Ok(())
    }

    /// Run the native module. The input is passed by the WASM program via the
    /// native module's special file.
    pub fn execute(&mut self, input: Vec<u8>) -> FileSystemResult<()> {
        if self.native_module.is_static() {
            // Look up native module in the static native modules table
            let mut nm = STATIC_NATIVE_MODULES.lock().map_err(|_| ErrNo::Inval)?;
            let nm = nm
                .get_mut(&self.native_module.name().to_string())
                .ok_or(ErrNo::Inval)?;
            if nm.try_parse(&input)? {
                nm.serve(&mut self.native_module_vfs, &input)?;
            }
        } else {
            info!("Preparing the native module's filesystem...");
            let top_level_files = self.prepare_fs()?;
            info!("OK");

            // Inject execution configuration into the native module's directory
            let mut file = File::create(
                self.native_module_directory
                    .join(strip_root_slash_str(EXECUTION_CONFIGURATION_FILE)),
            )?;
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

            let mount_mappings = self.build_mappings(top_level_files)?;
            let entry_point_tmp;
            let entry_point = match self.native_module.r#type() {
                NativeModuleType::Dynamic { entry_point, .. } => {
                    entry_point.to_str().ok_or(ErrNo::Inval)?
                }
                NativeModuleType::Provisioned { entry_point } => {
                    entry_point_tmp = self
                        .native_module_directory
                        .join(strip_root_slash_path(entry_point));
                    entry_point_tmp.to_str().ok_or(ErrNo::Inval)?
                }
                _ => panic!("should not happen"),
            };

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
                .spawn()?;

            info!("Propagating side effects to the VFS (access errors are ignored)...");
            // self.copy_fs_to_vfs(&PathBuf::from(""))?;
            // let _ = self.native_module_vfs.write_stdout(&output.stdout);
            // let _ = self.native_module_vfs.write_stderr(&output.stderr);
            // info!("OK");

            // self.teardown_fs()?;
        }

        Ok(())
    }
}

impl Drop for NativeModuleManager {
    /// Drop the native module manager.
    fn drop(&mut self) {
        // let _ = self.teardown_fs();
    }
}
