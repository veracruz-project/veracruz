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
use psa_crypto::{
    operations::cipher::{decrypt, encrypt},
    operations::key_management,
    types::algorithm::Cipher::Ctr,
    types::key::{Attributes, Lifetime, Policy, Type, UsageFlags},
};
use serde::Deserialize;
use std::path::PathBuf;
use wasi_types::ErrNo;

#[derive(Deserialize, Debug)]
pub(crate) struct AesCtrService {
    key: [u8; 16],
    iv: [u8; 16],
    input_path: PathBuf,
    output_path: PathBuf,
    is_encryption: bool,
}

impl Service for AesCtrService {
    fn name(&self) -> &str {
        "AesCtr Service"
    }

    fn serve(&mut self, fs: &mut FileSystem, _input: &[u8]) -> FileSystemResult<()> {
        // when reaching here, the `input` bytes are already parsed.
        println!("AesCtr is called");
        let AesCtrService {
            key,
            iv,
            input_path,
            output_path,
            is_encryption,
        } = self;
        println!("AesCtr input path: {:?}", input_path);
        println!("AesCtr output path: {:?}", input_path);
        let input = fs.read_file_by_absolute_path(&input_path)?;

        let mut usage_flags: UsageFlags = Default::default();
        usage_flags.set_encrypt();
        usage_flags.set_decrypt();
        let attributes = Attributes {
            key_type: Type::Aes,
            bits: 128,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: Ctr.into(),
            },
        };
        psa_crypto::init().map_err(|_| ErrNo::Canceled)?;
        let imported_key =
            key_management::import(attributes, None, &key[..]).map_err(|_| ErrNo::Canceled)?;
        let mut output = vec![0; input.len()];
        // can the enc or dec based on the `is_encryption` bool
        let length = if *is_encryption { encrypt } else { decrypt }(
            imported_key,
            Ctr,
            &input,
            &iv[..],
            &mut output,
        )
        .map_err(|_| ErrNo::Canceled)?;
        output.resize(length, 0);
        fs.write_file_by_absolute_path(&output_path, output, true)
    }

    /// For the purpose of demonstration, we always return true. In reality,
    /// this function may check validity of the `input`, and even buffer the result
    /// for further uses.
    fn try_parse(&mut self, input: &[u8]) -> FileSystemResult<bool> {
        let deserialized_input: AesCtrService =
            match postcard::from_bytes(&input).map_err(|_| ErrNo::Canceled) {
                Ok(o) => o,
                Err(_) => return Ok(false),
            };
        *self = deserialized_input;
        Ok(true)
    }
}

impl AesCtrService {
    pub fn new() -> Self {
        Self {
            key: [0; 16],
            iv: [0; 16],
            input_path: PathBuf::new(),
            output_path: PathBuf::new(),
            is_encryption: false,
        }
    }
}
