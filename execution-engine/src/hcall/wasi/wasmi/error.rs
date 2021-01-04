//! Error handling code specific to the WASMI execution engine.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use std::boxed::Box;

use super::super::common::RuntimePanic;

use wasmi::{HostError, RuntimeValue, Trap, TrapKind};
use wasi_types::ErrNo;

////////////////////////////////////////////////////////////////////////////////
// Veracruz host errors.
////////////////////////////////////////////////////////////////////////////////

#[typetag::serde]
impl HostError for RuntimePanic {}

////////////////////////////////////////////////////////////////////////////////
// Utility functions.
////////////////////////////////////////////////////////////////////////////////

/// Utility function which simplifies building a serialized Veracruz error code
/// to be passed back to the running WASM program executing on the WASMI engine.
#[inline]
pub(crate) fn mk_error_code<T>(e: ErrNo) -> Result<Option<RuntimeValue>, T> {
    // Safe as `ErrNo` is `repr(u16)`.
    Ok(Some(RuntimeValue::I32(i32::from(e as u16))))
}

/// Utility function which simplifies building a Veracruz host trap from a
/// Veracruz `RuntimePanic` value.
#[inline]
pub(crate) fn mk_host_trap<T>(trap: RuntimePanic) -> Result<T, Trap> {
    Err(Trap::new(TrapKind::Host(Box::new(trap))))
}