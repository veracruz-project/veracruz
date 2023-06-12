//! The Linux-specific runtime struct
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::{anyhow, Result};
use log::error;
use nix::libc::c_char;
use psa_attestation::{
    psa_initial_attest_get_token, psa_initial_attest_load_key, psa_initial_attest_remove_key,
};
use runtime_manager::{
    managers::{
        RuntimeManagerError,
        session_manager::generate_csr,
    },
    platform_runtime::PlatformRuntime,
};
use veracruz_utils::{
    runtime_manager_message::RuntimeManagerResponse,
    sha256::sha256,
};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// **TOTALLY INSECURE** root private key to use for Linux PSA attestation.
///
/// NOTE that Linux attestation is "mocked up" and totally insecure.  See the
/// attestation flow for AWS Nitro Enclaves for a secure attestation
/// implementation.  This is merely here for illustrative purposes.
static TOTALLY_INSECURE_ROOT_PRIVATE_KEY: [u8; 32] = [
    0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
    0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x05, 0x76, 0xa1, 0x44,
];

// Yes, I'm doing what you think I'm doing here. Each instance of the SGX root enclave
// will have the same public key. Yes, I'm embedding that key in the source
// code. I could come up with a complicated system for auto generating a key
// for each instance, and then use that key.
// That's what needs to be done if you want to productize this.
// That's not what I'm going to do for this research project
static TOTALLY_INSECURE_ROOT_PUBLIC_KEY: [u8; 65] = [
    0x4, 0x5f, 0x5, 0x5d, 0x39, 0xd9, 0xad, 0x60, 0x89, 0xf1, 0x33, 0x7e, 0x6c, 0xf9, 0x57, 0xe,
    0x6f, 0x84, 0x25, 0x5f, 0x16, 0xf8, 0xcd, 0x9c, 0xe4, 0xa0, 0xa2, 0x8d, 0x7a, 0x4f, 0xb7, 0xe4,
    0xd3, 0x60, 0x37, 0x2a, 0x81, 0x4f, 0x7, 0xc2, 0x5a, 0x24, 0x85, 0xbf, 0x47, 0xbc, 0x84, 0x47,
    0x40, 0xc5, 0x9b, 0xff, 0xff, 0xd2, 0x76, 0x32, 0x82, 0x4d, 0x76, 0x4d, 0xb4, 0x50, 0xee, 0x9f,
    0x22,
];

pub struct LinuxRuntime {
}

impl PlatformRuntime for LinuxRuntime {
    /// Performs a dummy implementation of native attestation using the insecure
    /// root private keys and computing the runtime manager hash.  If successful,
    /// produces a PSA attestation token binding the CSR hash, runtime manager hash,
    /// and challenge.
    fn attestation(&self, challenge: &Vec<u8>) -> Result<RuntimeManagerResponse> {

        let csr = generate_csr().map_err(|e| {
            error!(
                "Failed to generate certificate signing request.  Error produced: {:?}.",
                e
            );

            e
        })?;

        let csr_hash = sha256(&csr);

        let mut root_key_handle: u32 = 0;

        let ret = unsafe {
            psa_initial_attest_load_key(
                TOTALLY_INSECURE_ROOT_PRIVATE_KEY.as_ptr(),
                TOTALLY_INSECURE_ROOT_PRIVATE_KEY.len() as u64,
                &mut root_key_handle,
            )
        };

        if 0 != ret {
            return Err(anyhow!(RuntimeManagerError::UnsafeCallError(
                "psa_initial_attest_load_key",
                ret as u32,
            )));
        }

        let mut token = Vec::with_capacity(2048);
        let mut token_len: u64 = 0;

        // Section 3.2.1 of https://www.ietf.org/archive/id/draft-tschofenig-rats-psa-token-09.txt
        // EAT UEID of type RAND.
        // Length must be 33 bytes
        // first byte MUST be 0x01 (RAND)
        // next 32 bytes must be the hash of the key (Is this the public or private key? It's unclear, presume the public key because a hash of the private key could theoretically bleed info
        // about the private key)
        let public_key_hash = sha256(&TOTALLY_INSECURE_ROOT_PUBLIC_KEY);
        let mut enclave_name: Vec<u8> = Vec::new();
        enclave_name.push(0x01);
        enclave_name.extend_from_slice(&public_key_hash);

        let runtime_manager_hash: Vec<u8> = {
            let rmm = crate::RUNTIME_MANAGER_MEASUREMENT.lock().unwrap();
            (*rmm).to_vec()
        };

        let ret = unsafe {
            psa_initial_attest_get_token(
                runtime_manager_hash.as_ptr(),
                runtime_manager_hash.len() as u64,
                csr_hash.as_ptr() as *const u8,
                csr_hash.len() as u64,
                enclave_name.as_ptr() as *const c_char,
                enclave_name.len() as u64,
                challenge.as_ptr() as *const u8,
                challenge.len() as u64,
                token.as_mut_ptr() as *mut u8,
                token.capacity() as u64,
                &mut token_len as *mut u64,
            )
        };

        if 0 != ret {
            return Err(anyhow!(RuntimeManagerError::UnsafeCallError(
                "psa_initial_attest_get_token",
                ret as u32,
            )));
        }

        unsafe { token.set_len(token_len as usize) };

        let ret = unsafe { psa_initial_attest_remove_key(root_key_handle) };

        if 0 != ret {
            return Err(anyhow!(RuntimeManagerError::UnsafeCallError(
                "psa_initial_attest_remove_key",
                ret as u32,
            )));
        }

        return Ok(RuntimeManagerResponse::AttestationData(token, csr));
    }
}