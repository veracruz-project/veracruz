//! A native module for decryption and encryption in aead.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::fs::{FileSystem, FileSystemResult, Service};
use psa_crypto::operations::{aead, key_management};
use psa_crypto::types::algorithm::{Aead, AeadWithDefaultLengthTag};
use psa_crypto::types::key::{Attributes, Lifetime, Policy, Type, UsageFlags};
use psa_crypto::types::status::Error;
use std::convert::TryInto;

pub(crate) struct AeadService;

const DECRYPTED_DATA: [u8; 24] = [
    0x45, 0x35, 0xd1, 0x2b, 0x43, 0x77, 0x92, 0x8a, 0x7c, 0x0a, 0x61, 0xc9, 0xf8, 0x25, 0xa4, 0x86,
    0x71, 0xea, 0x05, 0x91, 0x07, 0x48, 0xc8, 0xef,
];

const ADDITIONAL_DATA: [u8; 32] = [
    0x40, 0xa2, 0x7c, 0x1d, 0x1e, 0x23, 0xea, 0x3d, 0xbe, 0x80, 0x56, 0xb2, 0x77, 0x48, 0x61, 0xa4,
    0xa2, 0x01, 0xcc, 0xe4, 0x9f, 0x19, 0x99, 0x7d, 0x19, 0x20, 0x6d, 0x8c, 0x8a, 0x34, 0x39, 0x51,
];

const NONCE: [u8; 13] = [
    0x48, 0xc0, 0x90, 0x69, 0x30, 0x56, 0x1e, 0x0a, 0xb0, 0xef, 0x4c, 0xd9, 0x72,
];

impl Service for AeadService {
    fn name(&self) -> &str {
        "Aead Service"
    }

    fn serve(&self, fs: &mut FileSystem, key_data: &[u8]) -> FileSystemResult<()> {
        let alg = Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm);
        let mut usage_flags: UsageFlags = Default::default();
        usage_flags.set_encrypt();
        let attributes = Attributes {
            key_type: Type::Aes,
            bits: 0,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: alg.into(),
            },
        };
        psa_crypto::init().unwrap();
        let my_key = key_management::import(attributes, None, key_data).unwrap();
        let output_buffer_size = attributes.aead_encrypt_output_size(alg.into(), DECRYPTED_DATA.len()).unwrap();
        let mut output_buffer = vec![0; output_buffer_size];
        let length = aead::encrypt(
            my_key,
            alg,
            &NONCE,
            &ADDITIONAL_DATA,
            &DECRYPTED_DATA,
            &mut output_buffer,
        )
        .unwrap();
        output_buffer.resize(length, 0);
        Ok(())
    }

    /// For the purpose of demonstration, we always return true. In reality,
    /// this function may check validity of the `input`, and even buffer the result 
    /// for further uses.
    fn try_parse(&self, _input: &[u8]) -> FileSystemResult<bool> {
        Ok(true)
    }
}
