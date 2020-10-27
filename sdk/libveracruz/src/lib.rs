//! libveracruz
//!
//! Rust support for writing Veracruz programs.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![no_std]

#[macro_use]
extern crate alloc;
extern crate byteorder;

pub mod data_description;
pub mod host;
pub mod return_code;
