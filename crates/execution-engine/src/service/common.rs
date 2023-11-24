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
    common::Execution,
    service::{echo::EchoService, postcard::PostcardService, aes::AesCounterModeService}
};
use std::{fs::{create_dir_all, remove_file}, sync::Once, path::{Path, PathBuf}, thread::{spawn, JoinHandle}};
use log::info;
use nix::{unistd, sys::stat};

/// Static native modules table.
pub static mut SERVICES: Services = Services::new();
static INIT_SERVICES: Once = Once::new();

/// Default input name pipeline file name.
static INPUT_FILE_NAME: &'static str = "input";
/// Default output name pipeline file name.
static OUTPUT_FILE_NAME: &'static str = "output";

fn remove_tmp_file(dir: &PathBuf) {
    let input_path = dir.join(INPUT_FILE_NAME);
    let output_path = dir.join(OUTPUT_FILE_NAME);

    let _ = remove_file(input_path.clone());
    let _ = remove_file(output_path.clone());
}

pub(crate) struct Service {
    dir: PathBuf,
    // Use the Option trick, allowing us to join the handle in `drop` function
    service: Option<JoinHandle<Result<()>>>,
}

impl Service {
    pub(crate) fn new(dir: PathBuf, mut service: Box<dyn Execution>) -> Result<Self> {
        create_dir_all(&dir)?;
        let dir_copy = dir.clone();

        let service = spawn(move || {
            remove_tmp_file(&dir_copy);

            let input_path = dir_copy.join(INPUT_FILE_NAME);
            let output_path = dir_copy.join(OUTPUT_FILE_NAME);

            info!("Bind a {:?} on input {input_path:?} and output {output_path:?}", service.name());
            // create new fifo and give read, write and execute rights to the owner
            let _ = unistd::mkfifo(&input_path, stat::Mode::S_IRWXU)?;
            let _ = unistd::mkfifo(&output_path, stat::Mode::S_IRWXU)?;

            loop{
                let _ = service.execute(dir_copy.as_path());
            }
        });

        Ok(Self {dir, service: Some(service)})
    }

}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(handler) = self.service.take() {
            let _ = handler.join();
        }

        remove_tmp_file(&self.dir);
    }
}

pub struct Services {
    pub(crate) services: Vec<Service>,
}

impl Services {
    pub const fn new() -> Self {
        Self{services: Vec::new()}
    }
    
    pub fn register<T: AsRef<Path>>(&mut self, dir: T, service: Box<dyn Execution>) -> Result<()> {
        self.services.push(Service::new(dir.as_ref().to_path_buf(), service)?);
        Ok(())
    }
}

pub fn initial_service() -> () {
    unsafe {
        INIT_SERVICES.call_once(||{
            SERVICES.register("/tmp/postcard/", Box::new(PostcardService::new())).unwrap();
            SERVICES.register("/tmp/echo/", Box::new(EchoService::new())).unwrap();
            SERVICES.register("/tmp/aes/", Box::new(AesCounterModeService::new())).unwrap();
        });
    }
    info!("Initialised service");
}
