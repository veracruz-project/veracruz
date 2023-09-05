//! A synthetic filesystem.
//!
//! This virtual file system(VFS) for Veracruz runtime and execution engine.
//! The VFS adopts most WASI API with *strict typing* and *Rust-style error handling*.
//! The Veracruz runtime will use this VFS directly, while any execution engine
//! can wrap all methods here to match the WASI API.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(clippy::too_many_arguments)]

use wasi_types::ErrNo;

////////////////////////////////////////////////////////////////////////////////
// Filesystem errors.
////////////////////////////////////////////////////////////////////////////////

/// Filesystem errors either return a result of type `T` or a defined error
/// code.  The return code `ErrNo::Success` is implicit if `Ok(result)` is ever
/// returned from a filesystem function.  The result `Err(ErrNo::Success)`
/// should never be returned.
pub type FileSystemResult<T> = Result<T, ErrNo>;


