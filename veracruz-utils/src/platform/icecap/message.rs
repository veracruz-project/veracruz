//! IceCap-specific message types for the Veracruz runtime manager.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use serde::{Serialize, Deserialize};

pub type Header = u32;
pub type SessionId = u32;

/// Type of requests from the host to the realm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Initialize { policy_json: String },
    Attestation { device_id: i32, challenge: Vec<u8> },
    CertificateChain { root_cert: Vec<u8>, compute_cert: Vec<u8> },
    NewTlsSession,
    CloseTlsSession(SessionId),
    SendTlsData(SessionId, Vec<u8>),
    GetTlsDataNeeded(SessionId),
    GetTlsData(SessionId),
}

/// Type of responses from the realm to the host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Initialize,
    Attestation { token: Vec<u8>, csr: Vec<u8> },
    CertificateChain,
    NewTlsSession(SessionId),
    CloseTlsSession,
    SendTlsData,
    GetTlsDataNeeded(bool),
    GetTlsData(bool, Vec<u8>),
    Error(Error),
}

/// Type of error responses from the realm to the host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Error {
    Unspecified,
}
