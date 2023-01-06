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

use policy_utils::principal::NativeModule;
use std::fmt::Debug;

pub struct Service {
    /// Native module
    native_module: NativeModule,
}

impl Service {
    /// Creates a Service.
    #[inline]
    pub fn new(native_module: NativeModule) -> Self
    {
        Self {
            native_module,
        }
    }

    /// Returns the native module.
    #[inline]
    pub fn native_module(&self) -> &NativeModule
    {
        &self.native_module
    }
}
impl Debug for Service {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Service: {}", self.native_module.interface_path().to_str().unwrap_or_default())
    }
}
