//! A native module for decryption and encryption of AEAD.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::fs::{FileSystem, FileSystemResult};
use crate::native_modules::common::Service;
use psa_crypto::{
    operations::aead::{decrypt, encrypt},
    operations::key_management,
    types::algorithm::{Aead, AeadWithDefaultLengthTag},
    types::key::{Attributes, Lifetime, Policy, Type, UsageFlags},
};
use serde::Deserialize;
use std::path::PathBuf;
use wasi_types::ErrNo;

#[derive(Deserialize, Debug)]
pub(crate) struct AeadService {
    /// Secret 128-bit AEAD key
    key: [u8; 16],
    /// Initialization vector
    iv: [u8; 16],
    /// Additional data
    aad: Vec<u8>,
    /// Path to input file that contains either the plaintext or cyphertext,
    /// depending on the flag `is_encryption`.
    input_path: PathBuf,
    /// Path to the result file.
    output_path: PathBuf,
    /// A (boolean) flag indicating if it is encryption, otherwise decryption.
    is_encryption: bool,
}

impl Service for AeadService {
    /// Return the name of this service
    fn name(&self) -> &str {
        "AEAD Service"
    }

    /// Triggers the service. The details of the service can be found in function
    /// `encryption_decryption`.
    /// Here is the enter point. It also erase the state unconditionally afterwards.
    fn serve(&mut self, fs: &mut FileSystem, _input: &[u8]) -> FileSystemResult<()> {
        // when reaching here, the `input` bytes are already parsed.
        let result = self.encryption_decryption(fs);
        // NOTE: erase all the states.
        self.reset();
        result
    }

    /// For the purpose of demonstration, we always return true. In reality,
    /// this function may check validity of the `input`, and even buffer the result
    /// for further uses.
    fn try_parse(&mut self, input: &[u8]) -> FileSystemResult<bool> {
        let deserialized_input: AeadService =
            match postcard::from_bytes(&input).map_err(|_| ErrNo::Canceled) {
                Ok(o) => o,
                Err(_) => return Ok(false),
            };
        *self = deserialized_input;
        Ok(true)
    }
}

impl AeadService {
    /// Create a new service, with empty internal state.
    pub fn new() -> Self {
        Self {
            key: [0; 16],
            iv: [0; 16],
            aad: Vec::<u8>::new(),
            input_path: PathBuf::new(),
            output_path: PathBuf::new(),
            is_encryption: false,
        }
    }

    /// The core service. It encrypts or decrypts, depending on the flag `is_encryption`, the input read
    /// from the path `input_path` using the `key` and `iv`, and writes the result to the file at `output_path`.
    fn encryption_decryption(&mut self, fs: &mut FileSystem) -> FileSystemResult<()> {
        let AeadService {
            key,
            iv,
            aad,
            input_path,
            output_path,
            is_encryption,
        } = self;
        let alg = Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm);

        // Read the input. The service must have the permission.
        let input = fs.read_file_by_absolute_path(&input_path)?;

        // Standard step to use AEAD interface in psa_crypto.
        let mut usage_flags: UsageFlags = Default::default();
        usage_flags.set_encrypt();
        usage_flags.set_decrypt();
        let attributes = Attributes {
            key_type: Type::Aes,
            bits: 128,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: alg.into(),
            },
        };
        psa_crypto::init().map_err(|_| ErrNo::Canceled)?;
        let imported_key =
            key_management::import(attributes, None, &key[..]).map_err(|_| ErrNo::Canceled)?;

        let output_buffer_size = if *is_encryption {
            attributes.aead_encrypt_output_size(alg.into(), input.len())
        } else {
            attributes.aead_decrypt_output_size(alg.into(), input.len())
        }
        .map_err(|_| ErrNo::Canceled)?;

        let mut output = vec![0; output_buffer_size];

        // call the enc or dec based on the `is_encryption` bool
        let length = if *is_encryption { encrypt } else { decrypt }(
            imported_key,
            alg.into(),
            &iv[..],
            &aad,
            &input,
            &mut output,
        )
        .map_err(|_| ErrNo::Canceled)?;

        // Write result. The result is resized to the actual size
        // returned by AEAD call, to avoid leaking sensitive information.
        output.resize(length, 0);
        fs.write_file_by_absolute_path(&output_path, output, true)
    }

    /// Reset the state, and erase the sensitive information.
    fn reset(&mut self) {
        self.key = [0; 16];
        self.iv = [0; 16];
        self.aad = Vec::<u8>::new();
        self.input_path = PathBuf::new();
        self.output_path = PathBuf::new();
        self.is_encryption = false;
    }
}
