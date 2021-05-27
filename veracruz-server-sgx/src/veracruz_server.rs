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
// TODO WIP: extend
pub enum VeracruzServerSGXError {
    #[error(display = "VeracruzServerSGX: SGXError: {:?}.", _0)]
    SGXError(sgx_types::sgx_status_t),
}

impl<T> From<std::sync::PoisonError<T>> for VeracruzServerSGXError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        VeracruzServerSGXError::LockError(format!("{:?}", error))
    }
}

impl From<sgx_types::sgx_status_t> for VeracruzServerSGXError {
    fn from(error: sgx_types::sgx_status_t) -> Self {
        match error {
            sgx_types::sgx_status_t::SGX_SUCCESS => {
                panic!("Expected an error code but received an success status")
            }
            e => VeracruzServerSGXError::SGXError(e),
        }
    }
}
