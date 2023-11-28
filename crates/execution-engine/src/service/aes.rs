//! A native module for decryption and encryption of AES counter mode.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::Result;
use crate::common::Execution;
use mbedtls::cipher::{Cipher, Decryption, Encryption, Fresh, Traditional};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::fs::{read, write};

/// The interface between of the Counter mode AES module.
#[derive(Deserialize, Debug)]
pub(crate) struct AesCounterModeService {
    /// Secret 128-bit AES key
    key: [u8; 16],
    /// Initialization vector
    iv: [u8; 16],
    /// Path to input file that contains either the plaintext or cyphertext,
    /// depending on the flag `is_encryption`.
    input_path: PathBuf,
    /// Path to the result file.
    output_path: PathBuf,
    /// A (boolean) flag indicating if it is encryption, otherwise decryption.
    is_encryption: bool,
}

impl Execution for AesCounterModeService {
    /// Return the name of this service
    fn name(&self) -> &str {
        Self::NAME
    }

    /// Triggers the service. The details of the service can be found in function
    /// `encryption_decryption`.
    /// Here is the enter point. It also erase the state unconditionally afterwards.
    fn execute(&mut self, dir: &Path) -> Result<()> {
        let input = dir.join("input");
        let output = dir.join("output");
        let buf = read(input)?;
        let deserialized_input: AesCounterModeService = postcard::from_bytes(&buf)?;
        *self = deserialized_input;
        // when reaching here, the `input` bytes are already parsed.
        let result = self.encryption_decryption();
        // NOTE: erase all the states.
        self.reset();
        // Write an output to inform the callee
        let _ = write(output, "0");
        result
    }
}

impl AesCounterModeService {
    pub(crate) const NAME: &'static str = "Counter mode AES Service";
    /// Create a new service, with empty internal state.
    pub fn new() -> Self {
        Self {
            key: [0; 16],
            iv: [0; 16],
            input_path: PathBuf::new(),
            output_path: PathBuf::new(),
            is_encryption: false,
        }
    }

    /// The core service. It encrypts or decrypts, depending on the flag `is_encryption`, the input read
    /// from the path `input_path` using the `key` and `iv`, and writes the result to the file at `output_path`.
    fn encryption_decryption(&mut self) -> Result<()> {
        let AesCounterModeService {
            key,
            iv,
            input_path,
            output_path,
            is_encryption,
        } = self;

        // Read the input. The service must have the permission.
        let input = read(&input_path)?;

        let mut output = Vec::new();

        if *is_encryption {
            let cypher: Cipher<Encryption, Traditional, Fresh> = mbedtls::cipher::Cipher::new(
                mbedtls::cipher::raw::CipherId::Aes,
                mbedtls::cipher::raw::CipherMode::CTR,
                key.len() as u32 * 8,
            )?;

            let block_size = cypher.block_size();
            // Mbed TLS requires the output buffer to be at least `ilen + block_size` long.
            // Cf. the documentation of `mbedtls_cipher_update()`
            let padded_size = input.len() + block_size;
            output.resize(padded_size, 0);

            cypher
                .set_key_iv(&key[..], &iv[..])?
                .encrypt(&input, &mut output)?;
        } else {
            let cypher: Cipher<Decryption, Traditional, Fresh> = mbedtls::cipher::Cipher::new(
                mbedtls::cipher::raw::CipherId::Aes,
                mbedtls::cipher::raw::CipherMode::CTR,
                key.len() as u32 * 8,
            )?;

            let block_size = cypher.block_size();
            // Mbed TLS requires the output buffer to be at least `ilen + block_size` long.
            // Cf. the documentation of `mbedtls_cipher_update()`
            let padded_size = input.len() + block_size;
            output.resize(padded_size, 0);

            cypher
                .set_key_iv(&key[..], &iv[..])?
                .decrypt(&input, &mut output)?;
        }

        // We only need as many bytes from the output as the input:
        output.resize(input.len(), 0);
        write(&output_path, output)?;
        Ok(())
    }

    /// Reset the state, and erase the sensitive information.
    fn reset(&mut self) {
        self.key = [0; 16];
        self.iv = [0; 16];
        self.input_path = PathBuf::new();
        self.output_path = PathBuf::new();
        self.is_encryption = false;
    }
}
