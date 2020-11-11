//! MexicoCity error
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use err_derive::Error;
#[cfg(feature = "tz")]
use std::sync::PoisonError;
#[cfg(feature = "sgx")]
use std::sync::PoisonError;

#[derive(Debug, Error)]
pub enum MexicoCityError {
    #[error(display = "MexicoCity: BajaError: {:?}.", _0)]
    BajaError(#[error(source)] baja::BajaError),
    #[error(display = "MexicoCity: ColimaError: {:?}.", _0)]
    ColimaError(#[error(source)] colima::ColimaError),
    #[error(display = "MexicoCity: VeracruzUtilError: {:?}.", _0)]
    VeracruzUtilError(#[error(source)] veracruz_utils::policy::VeracruzUtilError),
    #[error(display = "MexicoCity: FatalHostError: {:?}.", _0)]
    FatalHostError(#[error(source)] chihuahua::hcall::common::FatalHostError),
    #[error(display = "MexicoCity: HostProvisioningError: {:?}.", _0)]
    HostProvisioningError(#[error(source)] chihuahua::hcall::common::HostProvisioningError),
    #[error(display = "MexicoCity: Failed to obtain lock {:?}.", _0)]
    LockError(std::string::String),
    #[error(display = "MexicoCity: Uninitialized baja session in function {}.", _0)]
    UninitializedBajaSessionError(&'static str),
    #[cfg(feature = "sgx")]
    #[error(display = "Tabasco: SGXError: {:?}.", _0)]
    SGXError(sgx_types::sgx_status_t),
    #[error(display = "MexicoCity: {} failed with error code {:?}.", _0, _1)]
    UnsafeCallError(&'static str, u32),
    #[error(display = "MexicoCity: Received no data.")]
    NoDataError,
    #[error(display = "MexicoCity: Global policy requested an execution strategy unavailable on this platform.")]
    InvalidExecutionStrategyError,
    #[error(display = "MexicoCity: Unavailable baja session with ID {}.", _0)]
    UnavailableBajaSessionError(u64),
    #[error(display = "MexicoCity: Unavailable protocol state.")]
    UninitializedProtocolState,
    #[error(display = "MexicoCity: Unavailable income buffer with ID {}.", _0)]
    UnavailableIncomeBufferError(u64),
}

impl<T> From<PoisonError<T>> for MexicoCityError {
    fn from(error: PoisonError<T>) -> Self {
        MexicoCityError::LockError(format!("{:?}", error))
    }
}

#[cfg(feature = "sgx")]
impl From<sgx_types::sgx_status_t> for MexicoCityError {
    fn from(error: sgx_types::sgx_status_t) -> Self {
        match error {
            sgx_types::sgx_status_t::SGX_SUCCESS => {
                panic!("Expected an error code but received an success status")
            }
            e => MexicoCityError::SGXError(e),
        }
    }
}
