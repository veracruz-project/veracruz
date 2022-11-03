//! A native module for ML inference on TensorFlow Lite.
//! Takes an input tensor, feeds it to the model and outputs an output tensor.
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
use lazy_static::*;
use libc::c_int;
use serde::Deserialize;
use std::env::{current_dir, set_current_dir};
use std::fs::{create_dir, create_dir_all, remove_dir_all, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tflite::ops::builtin::BuiltinOpResolver;
use tflite::{FlatBufferModel, InterpreterBuilder};
use wasi_types::ErrNo;

lazy_static! {
    // Current directory before moving to the module's directory
    static ref WORK_DIR: PathBuf = current_dir().unwrap_or(PathBuf::from(""));

    // The native module executes in a dedicated directory to mitigate data
    // leaks
    static ref MODULE_DIR: PathBuf = WORK_DIR.clone().join("tflite_inference_service");
}

/// Module's API.
#[derive(Deserialize, Debug)]
pub(crate) struct TfLiteInferenceService {
    // TODO: support several inputs and outputs
    /// Path to the input tensor to be fed to the network.
    input_tensor_path: PathBuf,
    /// Path to the model serialized with FlatBuffers.
    model_path: PathBuf,
    /// Path to the output tensor containing the result of the prediction.
    output_tensor_path: PathBuf,
    /// Number of CPU threads to use for the TensorFlow Lite interpreter.
    num_threads: c_int,
}

impl Service for TfLiteInferenceService {
    /// Return the name of this service
    fn name(&self) -> &str {
        "TensorFlow Lite Inference Service"
    }

    /// Triggers the service. The details of the service can be found in
    /// function `infer`.
    /// Here is the enter point. It also erases the state unconditionally
    /// afterwards.
    fn serve(&mut self, fs: &mut FileSystem, _input: &[u8]) -> FileSystemResult<()> {
        // when reaching here, the `input` bytes are already parsed.

        // Prepare module's directory
        create_dir(MODULE_DIR.as_path()).map_err(|_| ErrNo::Access)?;
        set_current_dir(MODULE_DIR.as_path())?;

        let result = self.infer(fs);
        // NOTE: erase all the states and files passed to the module and created
        // during execution
        self.reset();
        result
    }

    /// For the purpose of demonstration, we always return true. In reality,
    /// this function may check validity of the `input`, and even buffer the
    /// result for further uses.
    fn try_parse(&mut self, input: &[u8]) -> FileSystemResult<bool> {
        let deserialized_input: TfLiteInferenceService =
            match postcard::from_bytes(&input).map_err(|_| ErrNo::Canceled) {
                Ok(o) => o,
                Err(_) => return Ok(false),
            };
        *self = deserialized_input;
        Ok(true)
    }
}

impl TfLiteInferenceService {
    /// Create a new service, with empty internal state.
    pub fn new() -> Self {
        Self {
            input_tensor_path: PathBuf::new(),
            model_path: PathBuf::new(),
            output_tensor_path: PathBuf::new(),
            num_threads: -1,
        }
    }

    /// The core service. It loads the model pointed by `model_path` then feeds
    /// the input read from `input_tensor_path` to the model, and writes the
    /// resulting tensor to the file at `output_tensor_path`.
    /// The interpreter can be further configured with `num_threads`.
    fn infer(&mut self, fs: &mut FileSystem) -> FileSystemResult<()> {
        let TfLiteInferenceService {
            input_tensor_path,
            model_path,
            output_tensor_path,
            num_threads,
        } = self;

        let input_file_paths: [&PathBuf; 2] = [input_tensor_path, model_path];

        // Copy input files from the VFS to the kernel filesystem, preserving
        // the file tree. At that point, we are already in the module's
        // directory
        for file_path in input_file_paths {
            let parent_path = file_path.as_path().parent().ok_or(ErrNo::NoEnt)?;
            let _ = create_dir_all(parent_path);
            let buffer = fs.read_file_by_absolute_path(Path::new("/").join(file_path))?;
            let mut file = File::create(file_path)?;
            file.write_all(&buffer)?;
        }

        // Build model and interpreter
        let model = FlatBufferModel::build_from_file(model_path).map_err(|_| ErrNo::Canceled)?;
        let resolver = BuiltinOpResolver::default();
        let builder = InterpreterBuilder::new(&model, &resolver).map_err(|_| ErrNo::Canceled)?;
        let mut interpreter = builder.build().map_err(|_| ErrNo::Canceled)?;

        // Configure interpreter
        // XXX: This function call is commented out as it results in a write to
        // stdout, which currently fails on Linux (cf.
        // https://github.com/veracruz-project/veracruz/issues/565)
        //interpreter.set_num_threads(*num_threads);

        interpreter
            .allocate_tensors()
            .map_err(|_| ErrNo::Canceled)?;

        // Load and configure inputs.
        // XXX: We assume a single input for now
        let inputs = interpreter.inputs().to_vec();
        assert_eq!(inputs.len(), 1);
        let input_index = inputs[0];
        let mut input_file = File::open(&input_tensor_path)?;
        input_file.read_exact(
            interpreter
                .tensor_data_mut(input_index)
                .map_err(|_| ErrNo::Canceled)?,
        )?;

        interpreter.invoke().map_err(|_| ErrNo::Canceled)?;

        // Get outputs
        // XXX: We assume a single output for now
        let outputs = interpreter.outputs().to_vec();
        let output_index = outputs[0];
        let output = interpreter
            .tensor_data(output_index)
            .map_err(|_| ErrNo::Canceled)?;

        // Write outputs to VFS
        fs.write_file_by_absolute_path(
            Path::new("/").join(output_tensor_path),
            output.to_vec(),
            true,
        )?;

        Ok(())
    }

    /// Reset the state, and erase the sensitive information.
    fn reset(&mut self) {
        self.input_tensor_path = PathBuf::new();
        self.model_path = PathBuf::new();
        self.output_tensor_path = PathBuf::new();
        self.num_threads = -1;

        // Go back to work directory and delete files passed to the module and
        // created during execution
        set_current_dir(WORK_DIR.as_path()).unwrap();
        remove_dir_all(MODULE_DIR.as_path()).unwrap();
    }
}
