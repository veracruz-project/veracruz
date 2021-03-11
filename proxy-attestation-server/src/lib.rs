//! The Veracruz proxy attestation server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;

mod attestation;

mod orm;

pub mod server;

pub mod error;
