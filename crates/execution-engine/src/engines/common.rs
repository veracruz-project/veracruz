//! Common code for any implementation of WASI
//!
//! This module contains:
//! - An interface for handling memory access.
//! - An interface for executing a program.
//! - A Wasi wrapper which wraps the strictly Wasi-like API in the virtual file
//!   system, and converts Wasm number- and address-based parameters to
//!   properly-typed parameters with Rust-style error handling (and vice versa).
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
use std::path::Path;

////////////////////////////////////////////////////////////////////////////////
// The strategy trait.
////////////////////////////////////////////////////////////////////////////////

/// This is what an execution strategy exposes to clients outside of this
/// library.  This functionality is sufficient to implement both
/// `freestanding-execution-engine` and `runtime-manager` and if any
/// functionality is missing that these components require then it should be
/// added to this trait and implemented for all supported implementation
/// strategies.
pub trait ExecutionEngine: Send {
    /// Entry point for the execution engine: invokes the program at `path`,
    /// Returns `Ok(())` if it successfully executed, 
    /// or returns `Err(e)` if some fatal execution
    /// engine error occurred at runtime causing the pipeline to abort.
    fn serve(&mut self, path: &Path) -> Result<()>;
}
