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
use std::path::PathBuf;
#[cfg(not(feature = "icecap"))]
use std::{
    ffi::OsString,
    os::unix::ffi::OsStringExt,
};
use wasi_types::ErrNo;

pub(crate) struct AeadService;

const ADDITIONAL_DATA: [u8; 0] = [ ];

impl Service for AeadService {
    fn name(&self) -> &str {
        "Aead Service"
    }

    fn serve(&self, fs: &mut FileSystem, key_data: &[u8]) -> FileSystemResult<()> {
        println!("Aead is called");
        let key = &key_data[0..16];
        let nonce = &key_data[16..13+16];
        #[cfg(feature = "icecap")]
        let input_path = 
            PathBuf::from(String::from_utf8(key_data[13+16..key_data.len()-1].to_vec()).map_err(|_| ErrNo::Canceled));
        #[cfg(not(feature = "icecap"))]
        let input_path = 
            PathBuf::from(OsString::from_vec(key_data[13+16..key_data.len()-1].to_vec()));
        println!("Aead input path: {:?}", input_path);
        let input = fs.read_file_by_absolute_path(&input_path)?;

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
        psa_crypto::init().map_err(|_| ErrNo::Canceled)?;
        let my_key = key_management::import(attributes, None, key).map_err(|_| ErrNo::Canceled)?;
        let output_buffer_size = attributes.aead_encrypt_output_size(alg.into(), input.len()).map_err(|_| ErrNo::Canceled)?;
        let mut output_buffer = vec![0; output_buffer_size];
        let length = aead::encrypt(
            my_key,
            alg,
            nonce,
            &ADDITIONAL_DATA,
            &input,
            &mut output_buffer,
        )
        .map_err(|_| ErrNo::Canceled)?;
        output_buffer.resize(length, 0);
        fs.write_file_by_absolute_path(&input_path, output_buffer, true)
    }

    /// For the purpose of demonstration, we always return true. In reality,
    /// this function may check validity of the `input`, and even buffer the result 
    /// for further uses.
    fn try_parse(&self, input: &[u8]) -> FileSystemResult<bool> {
        //             key + nonce       `ZERO`-end string
        Ok(input.len() > (16 + 13) && input[input.len()-1] == 0)
    }
}

impl AeadService {
    pub fn new() -> Self {
        Self{}
    }
}
