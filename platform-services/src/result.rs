//! Error codes for platform services
//!
//! A platform service can end in one of three ways:
//! 
//! 1. *Success*, in which the platform service successfully executed,
//! 2. *Unavailable*, in which the service in question is not available on
//!    the current platfrom.  For example: a trusted time source may not be
//!    available on all platforms that Veracruz supports.
//! 3. *UnknownError*: the service is available, but there was some error
//!    raised during service execution.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

//! Error codes describing the result of a platform service function.
#[derive(Debug)]
pub enum Result<T> {
    /// The operation completed successfully.
    Success(T),
    /// The operation is unavailable on this platform.
    Unavailable,
    /// An unknown error occurred during the execution of the operation.
    UnknownError,
}
