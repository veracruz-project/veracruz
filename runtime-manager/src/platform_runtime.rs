use anyhow::Result;
use veracruz_utils::{
    runtime_manager_message::RuntimeManagerResponse,
};
pub trait PlatformRuntime {
    fn attestation(&self, challenge: &Vec<u8>) -> Result<RuntimeManagerResponse>;
}
