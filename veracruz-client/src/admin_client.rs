//! The Veracruz admin client
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::error::VeracruzClientError;
use std::time::Duration;
use veracruz_utils::policy::policy::Policy;
use serde::{Serialize, Deserialize};


/// Provides VeracruzAdminClient, a client API for administrative actions
/// that don't require a policy
///
/// For interaction with the actual enclave see VeracruzClient
///
#[derive(Debug)]
pub struct VeracruzAdminClient {
    url: String,
}

/// Status of enclaves running on a Veracruz server, returned by
/// enclave_list
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct VeracruzEnclaveStatus {
    pub policy_hash: String,
    pub id: u32,
    pub uptime: Duration,
}

impl VeracruzAdminClient {
    /// Create a new VeracruzAdminClient to talk to the given server
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned()
        }
    }

    /// Setup an enclave with the provided policy
    pub fn enclave_setup(&mut self, policy_json: &str) -> Result<(), VeracruzClientError> {
        // check that policy is valid
        Policy::from_json(&policy_json)?;

        // send request
        let path = format!("http://{}/enclave_setup", self.url);
        let ret = reqwest::Client::new()
            .post(&path)
            .body(policy_json.to_owned())
            .send()?;
        if ret.status() != reqwest::StatusCode::OK {
            Err(VeracruzClientError::InvalidReqwestError(ret.status()))?;
        }

        Ok(())
    }

    /// Teardown an enclave
    pub fn enclave_teardown(&mut self) -> Result<(), VeracruzClientError> {
        // send request
        let path = format!("http://{}/enclave_teardown", self.url);
        let ret = reqwest::Client::new()
            .post(&path)
            .send()?;
        if ret.status() != reqwest::StatusCode::OK {
            Err(VeracruzClientError::InvalidReqwestError(ret.status()))?;
        }

        Ok(())
    }

    /// Query a list of running enclaves
    pub fn enclave_list(&self) -> Result<Vec<VeracruzEnclaveStatus>, VeracruzClientError> {
        // send request
        let path = format!("http://{}/enclave_list", self.url);
        let mut ret = reqwest::Client::new()
            .get(&path)
            .send()?;
        if ret.status() != reqwest::StatusCode::OK {
            Err(VeracruzClientError::InvalidReqwestError(ret.status()))?;
        }

        let text = ret.text()?;
        let list: Vec<VeracruzEnclaveStatus> = serde_json::from_str(&text)?;
        Ok(list)
    }

    /// Get the policy governing an enclave's computation
    ///
    /// Note, despite containing JSON, a textual representation of the policy
    /// is returned. This is because the policy's textual representation matters
    /// as this determines the hash of its value. 
    ///
    pub fn enclave_policy(&self) -> Result<String, VeracruzClientError> {
        // send request
        let path = format!("http://{}/enclave_policy", self.url);
        let mut ret = reqwest::Client::new()
            .get(&path)
            .send()?;
        if ret.status() != reqwest::StatusCode::OK {
            Err(VeracruzClientError::InvalidReqwestError(ret.status()))?;
        }

        Ok(ret.text()?)
    }
}
