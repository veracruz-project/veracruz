//! The PlatformRuntime interface that platform-specific code must implement
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.
//!
use std::sync::mpsc::Sender;

use anyhow::Result;
use execution_engine::fs::BroadcastEvent;
use veracruz_utils::runtime_manager_message::RuntimeManagerResponse;

pub trait PlatformRuntime {
    fn attestation(&self, challenge: &Vec<u8>) -> Result<RuntimeManagerResponse>;

    fn sender(&self) -> Sender<BroadcastEvent>;
}
