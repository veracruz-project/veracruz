//! Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use actix_http::ResponseBuilder;
use actix_web::{error, http::StatusCode, HttpResponse};
use curl::easy::{Easy, List};
use err_derive::Error;
use log::debug;
use std::io::Read;

pub type VeracruzServerResponder = Result<String, VeracruzServerError>;

#[derive(Debug, Error)]
pub enum VeracruzServerError {
// TODO WIP: extend it
}

impl From<sgx_types::sgx_status_t> for VeracruzServerError {
    fn from(error: sgx_types::sgx_status_t) -> Self {
        match error {
            sgx_types::sgx_status_t::SGX_SUCCESS => {
                panic!("Expected an error code but received an success status")
            }
            e => VeracruzServerError::SGXError(e),
        }
    }
}
