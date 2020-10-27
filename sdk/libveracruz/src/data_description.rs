//! Data description macros
//!
//! Macros for writing the result of a Veracruz program back to the host.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::host;
use crate::return_code;
use serde::Serialize;

/// A function that writes a result back to the Veracruz host. The function
/// fails with [`result_type::ErrorCode::InvariantFailed`] if the return value cannot be encoded as
/// Pinecone, or if the synthesized function has been called once already.
pub fn write_result<T: Serialize>(result: T) -> return_code::Veracruz {
    match pinecone::to_vec(&result) {
        Err(_err) => return_code::fail_invariant_failed(),
        Ok(bytes) => match host::write_output(&bytes) {
            host::HCallReturnCode::Success(_succ) => return_code::success(),
            _otherwise => return_code::fail_invariant_failed(),
        },
    }
}
