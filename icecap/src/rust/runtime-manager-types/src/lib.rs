//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![no_std]

use serde::{Deserialize, Serialize};
use libc::*;


// mmap things

pub use libc::PROT_NONE;
pub use libc::PROT_READ;
pub use libc::PROT_WRITE;
pub use libc::PROT_EXEC;
pub use libc::MAP_ANON;
pub use libc::MAP_PRIVATE;
pub use libc::MAP_FIXED;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MmapMmapRequest {
    pub addr: uintptr_t,
    pub length: size_t,
    pub prot: c_int,
    pub flags: c_int,
    pub fd: c_int,
    pub offset: size_t,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MmapMunmapRequest {
    pub addr: uintptr_t,
    pub length: size_t,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MmapRequest {
    MmapRequest(MmapMmapRequest),
    MunmapRequest(MmapMunmapRequest),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MmapResponse {
    MmapResponse(uintptr_t),
    MunmapResponse(c_int),
}
