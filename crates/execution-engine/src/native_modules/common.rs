//! Native modules for Execution Engine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::Result;
use crate::{
    native_modules::{echo::EchoService, postcard::PostcardService, aes::AesCounterModeService}
};
use std::{fs::{create_dir_all, remove_file}, sync::Once, path::{Path, PathBuf}, thread::{spawn, JoinHandle}};
use log::info;
use nix::{unistd, sys::stat};

/// Specifications for static native module crates.
/// See `policy_utils::principal::NativeModule` and `generate-policy` for more
/// details on static native modules.
pub trait StaticNativeModule: Send {
    fn name(&self) -> &str;
    /// The FS will prepare the Input and call the serve function at an appropriate time.
    /// Result may depend on the configure.
    fn serve(&mut self, input: &Path, output: &Path) -> Result<()>;
}

// Static native modules table.
// Note that only the ones specified in the policy will actually be exposed to
// WASM programs over the VFS.
pub static mut SERVICES: Services = Services::new();
static INIT_SERVICES: Once = Once::new();

pub(crate) struct Service {
    input: PathBuf,
    output: PathBuf,
    // Use the Option trick, allowing us to join the handle in drop function
    service: Option<JoinHandle<Result<()>>>,
}

impl Service {
    pub(crate) fn new(input: PathBuf, output: PathBuf, mut service: Box<dyn StaticNativeModule>) -> Result<Self> {
        let input_copy = input.clone();
        let output_copy = output.clone();
        let service = spawn(move || {

            info!("Remove old service input {input_copy:?} and output {output_copy:?}");
            let _ = remove_file(input_copy.clone());
            let _ = remove_file(output_copy.clone());

            if let Some(parent) = input_copy.parent() {
                create_dir_all(parent)?;
            }
            
            if let Some(parent) = output_copy.parent() {
                create_dir_all(parent)?;
            }

            info!("Bind a {:?} on input {input_copy:?} and output {output_copy:?}", service.name());
            // create new fifo and give read, write and execute rights to the owner
            let _ = unistd::mkfifo(&input_copy, stat::Mode::S_IRWXU)?;
            let _ = unistd::mkfifo(&output_copy, stat::Mode::S_IRWXU)?;

            loop{
                let _ = service.serve(input_copy.as_path(), output_copy.as_path());
            }
        });

        Ok(Self {input, output, service: Some(service)})
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(handler) = self.service.take() {
            let _ = handler.join();
        }
        let _ = remove_file(self.input.clone());
        let _ = remove_file(self.output.clone());
    }
}

pub struct Services {
    pub(crate) services: Vec<Service>,
}

impl Services {
    pub const fn new() -> Self {
        Self{services: Vec::new()}
    }
    
    pub fn register<T: AsRef<Path>, K: AsRef<Path>>(&mut self, input: T, output: K, service: Box<dyn StaticNativeModule>) -> Result<()> {
        self.services.push(Service::new(input.as_ref().to_path_buf(), output.as_ref().to_path_buf(), service)?);
        Ok(())
    }
}

pub fn initial_service() -> () {
    unsafe {
        INIT_SERVICES.call_once(||{
            SERVICES.register("/tmp/postcard/input", "/tmp/postcard/output", Box::new(PostcardService::new())).unwrap();
            SERVICES.register("/tmp/echo/input", "/tmp/echo/output", Box::new(EchoService::new())).unwrap();
            SERVICES.register("/tmp/aes/input", "/tmp/aes/output", Box::new(AesCounterModeService::new())).unwrap();
        });
    }
    info!("Initialised service");
}
