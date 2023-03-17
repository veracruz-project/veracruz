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

use crate::fs::{FileSystem, FileSystemResult};

/// Specifications for static native modules, i.e. native modules which are
/// always part of the Veracruz runtime and don't have to be loaded as separate
/// binaries.
/// Despite their static behaviour, they have to be explicitly declared in the
/// policy file to be used. See `policy_utils::principal::NativeModule` and
/// `generate-policy` for more details.
pub trait StaticNativeModule: Send {
    fn name(&self) -> &str;
    //fn configure(&mut self, config: Self::Configuration) -> FileSystemResult<()>;
    // The FS will prepare the Input and call the serve function at an appropriate time.
    // Result may depend on the configure.
    fn serve(&mut self, fs: &mut FileSystem, input: &[u8]) -> FileSystemResult<()>;
    // try_parse may buffer any result, hence we pass a mutable self here.
    fn try_parse(&mut self, input: &[u8]) -> FileSystemResult<bool>;
}
