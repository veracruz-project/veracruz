//! A native module for ML inference.
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
use darknet::{BBox, Image, Network};
use serde::Deserialize;
use std::path::PathBuf;
use wasi_types::ErrNo;

/// The interface between of the Counter mode AES module.
#[derive(Deserialize, Debug)]
pub(crate) struct MlInferenceService {
    /// Path to the input to be passed through the model
    input_path: PathBuf,
    /// Path to the model. TODO: do we expect a format?
    model_path: PathBuf,
    /// Path to the result file.
    output_path: PathBuf,
}

impl Service for MlInferenceService {
    /// Return the name of this service
    fn name(&self) -> &str {
        "Machine Learning Inference Service"
    }

    /// Triggers the service. The details of the service can be found in function
    /// `encryption_decryption`.
    /// Here is the enter point. It also erase the state unconditionally afterwards.
    fn serve(&mut self, fs: &mut FileSystem, _input: &[u8]) -> FileSystemResult<()> {
        // when reaching here, the `input` bytes are already parsed.
        let result = self.infer(fs);
        // NOTE: erase all the states.
        self.reset();
        result
    }

    /// For the purpose of demonstration, we always return true. In reality,
    /// this function may check validity of the `input`, and even buffer the result
    /// for further uses.
    fn try_parse(&mut self, input: &[u8]) -> FileSystemResult<bool> {
        let deserialized_input: MlInferenceService =
            match postcard::from_bytes(&input).map_err(|_| ErrNo::Canceled) {
                Ok(o) => o,
                Err(_) => return Ok(false),
            };
        *self = deserialized_input;
        Ok(true)
    }
}

impl MlInferenceService {
    /// Create a new service, with empty internal state.
    pub fn new() -> Self {
        Self {
            input_path: PathBuf::new(),
            model_path: PathBuf::new(),
            output_path: PathBuf::new(),
        }
    }

    /// The core service. It encrypts or decrypts, depending on the flag `is_encryption`, the input read
    /// from the path `input_path` using the `key` and `iv`, and writes the result to the file at `output_path`.
    fn infer(&mut self, fs: &mut FileSystem) -> FileSystemResult<()> {
        println!("<<infer");
        let MlInferenceService {
            input_path,
            model_path,
            output_path,
        } = self;

        println!("{:?}", input_path);
        println!("{:?}", model_path);
        println!("{:?}", output_path);
        let mut net = Network::load(input_path.clone(), Some(model_path), false).map_err(|_| ErrNo::Canceled)?;

        // Read the input. The service must have the permission.
        let input = fs.read_file_by_absolute_path(&input_path)?;

        // Write result. The result is resized to the actual size 
        // returned by AES call, to avoid leaking sensitive information.
        let mut output = vec![0; input.len()];
        //output.resize(length, 0);
        fs.write_file_by_absolute_path(&output_path, output, true)
    }

    /// Reset the state, and erase the sensitive information.
    fn reset(&mut self) {
        self.input_path = PathBuf::new();
        self.model_path = PathBuf::new();
        self.output_path = PathBuf::new();
    }
}
