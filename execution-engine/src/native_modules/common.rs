//! Native modules for Execution Engine.
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
    fs::{FileSystem, FileSystemResult},
    native_modules::{aead::AeadService, aes::AesCounterModeService, postcard::PostcardService}
};
use lazy_static::lazy_static;
use std::{collections::HashMap, sync::Mutex};

/// Specifications for static native modules, i.e. native modules which are
/// always part of the Veracruz runtime and don't have to be loaded as separate
/// binaries.
/// Despite their static behaviour, they have to be explicitly declared in the
/// policy file to be used in a computation. See
/// `policy_utils::principal::NativeModule` and `generate-policy` for more
/// details.
pub trait StaticNativeModule: Send {
    fn name(&self) -> &str;
    //fn configure(&mut self, config: Self::Configuration) -> FileSystemResult<()>;
    // The FS will prepare the Input and call the serve function at an appropriate time.
    // Result may depend on the configure.
    fn serve(&mut self, fs: &mut FileSystem, input: &[u8]) -> FileSystemResult<()>;
    // try_parse may buffer any result, hence we pass a mutable self here.
    fn try_parse(&mut self, input: &[u8]) -> FileSystemResult<bool>;
}

// Static native modules table.
// Note that only the ones specified in the policy will actually be exposed to
// WASM programs over the VFS.
lazy_static! {
    pub static ref STATIC_NATIVE_MODULES: Mutex<HashMap<String, Box<dyn StaticNativeModule>>> = {
        let mut h = HashMap::<String, Box<dyn StaticNativeModule>>::new();
        let list: Vec<Box<dyn StaticNativeModule>> = vec![
            Box::new(AeadService::new()),
            Box::new(AesCounterModeService::new()),
            Box::new(PostcardService::new()),
        ];
        for nm in list {
            h.insert(nm.name().to_string(), nm);
        }
        Mutex::new(h)
    };
}
