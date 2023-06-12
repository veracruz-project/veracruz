//! The Icecap-specific runtime struct
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::Result;
use runtime_manager_enclave::{
    managers::session_manager::{
        generate_csr,
        init_session_manager,
    },
    platform_runtime::PlatformRuntime,
};
use veracruz_utils::{
    runtime_manager_message::RuntimeManagerResponse,
    sha256::sha256,
};

const EXAMPLE_PUBLIC_KEY: [u8; 65] = [
    0x4, 0x5f, 0x5, 0x5d, 0x39, 0xd9, 0xad, 0x60, 0x89, 0xf1, 0x33, 0x7e, 0x6c, 0xf9, 0x57,
    0xe, 0x6f, 0x84, 0x25, 0x5f, 0x16, 0xf8, 0xcd, 0x9c, 0xe4, 0xa0, 0xa2, 0x8d, 0x7a, 0x4f,
    0xb7, 0xe4, 0xd3, 0x60, 0x37, 0x2a, 0x81, 0x4f, 0x7, 0xc2, 0x5a, 0x24, 0x85, 0xbf, 0x47,
    0xbc, 0x84, 0x47, 0x40, 0xc5, 0x9b, 0xff, 0xff, 0xd2, 0x76, 0x32, 0x82, 0x4d, 0x76, 0x4d,
    0xb4, 0x50, 0xee, 0x9f, 0x22,
];

const EXAMPLE_PRIVATE_KEY: [u8; 32] = [
    0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54,
    0xd0, 0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x05, 0x76,
    0xa1, 0x44,
];

const EXAMPLE_HASH: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
    0xef, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d,
    0xca, 0xfe,
];

const ROOT_PRIVATE_KEY: &[u8] = &EXAMPLE_PRIVATE_KEY;

const RUNTIME_MANAGER_HASH: &[u8] = &EXAMPLE_HASH;

pub struct IcecapRuntime {
}

impl PlatformRuntime for IcecapRuntime {
    /// Performs a dummy implementation of native attestation using the insecure
    /// root private keys and computing the runtime manager hash.  If successful,
    /// produces a PSA attestation token binding the CSR hash, runtime manager hash,
    /// and challenge.
    fn attestation(&self, challenge: &Vec<u8>) -> Result<RuntimeManagerResponse> {
        init_session_manager()?;
        let csr = generate_csr()?;
        let root_private_key = &ROOT_PRIVATE_KEY;
        let enclave_hash = &RUNTIME_MANAGER_HASH;
        let csr_hash = sha256(&csr);

        let mut root_key_handle: u32 = 0;
        assert_eq!(0, unsafe {
            psa_attestation::psa_initial_attest_load_key(
                root_private_key.as_ptr(),
                root_private_key.len() as u64,
                &mut root_key_handle,
            )
        });

        // Section 3.2.1 of https://www.ietf.org/archive/id/draft-tschofenig-rats-psa-token-09.txt
        // EAT UEID of type RAND.
        // Length must be 33 bytes
        // first byte MUST be 0x01 (RAND)
        // next 32 bytes must be the hash of the key (Is this the public or private key? It's unclear, presume the public key because a hash of the private key could theoretically bleed info
        // about the private key)
        let public_key_hash = sha256(&EXAMPLE_PUBLIC_KEY);
        let mut enclave_name: Vec<u8> = Vec::new();
        enclave_name.push(0x01);
        enclave_name.extend_from_slice(&public_key_hash);

        let mut token: Vec<u8> = Vec::with_capacity(2048);
        let mut token_len: u64 = 0;
        assert_eq!(0, unsafe {
            psa_attestation::psa_initial_attest_get_token(
                enclave_hash.as_ptr() as *const u8,
                enclave_hash.len() as u64,
                csr_hash.as_ptr() as *const u8,
                csr_hash.len() as u64,
                enclave_name.as_ptr() as *const u8,
                enclave_name.len() as u64,
                challenge.as_ptr() as *const u8,
                challenge.len() as u64,
                token.as_mut_ptr() as *mut u8,
                token.capacity() as u64,
                &mut token_len as *mut u64,
            )
        });
        unsafe { token.set_len(token_len as usize) };

        assert_eq!(0, unsafe {
            psa_attestation::psa_initial_attest_remove_key(root_key_handle)
        });

        return Ok(RuntimeManagerResponse::AttestationData(token, csr));
    }
}