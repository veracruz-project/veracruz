//! The Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![cfg_attr(any(feature = "icecap"), no_main)]
#![cfg_attr(any(feature = "icecap"), feature(rustc_private))]
#![cfg_attr(any(feature = "icecap"), feature(format_args_nl))]

pub mod common_runtime;
pub mod managers;
pub mod platforms;
pub mod platform_runtime;
