//! A native module for ML inference on Darknet.
//! Takes an input image, feeds it to the model and outputs a list of detected
//! objects.
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
use darknet::{BBox, Detection, Image, Network};
use lazy_static::*;
use serde::Deserialize;
use std::cmp::Ordering;
use std::env::{current_dir, set_current_dir};
use std::fmt::Write as _;
use std::fs::{create_dir, create_dir_all, read_to_string, remove_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use wasi_types::ErrNo;

lazy_static! {
    // Current directory before moving to the module's directory
    static ref WORK_DIR: PathBuf = current_dir().unwrap_or(PathBuf::from(""));

    // The native module executes in a dedicated directory to mitigate data
    // leaks
    static ref MODULE_DIR: PathBuf = WORK_DIR.clone().join("darknet_inference_service");
}

/// Module's API.
#[derive(Deserialize, Debug)]
pub(crate) struct DarknetInferenceService {
    /// Path to the input to be fed to the network.
    input_path: PathBuf,
    /// Path to the model's configuration.
    cfg_path: PathBuf,
    /// Path to the actual model (weights).
    model_path: PathBuf,
    /// Path to the labels file containing all the objects that can be detected.
    labels_path: PathBuf,
    /// Path to the output file containing the result of the prediction.
    output_path: PathBuf,
}

impl Service for DarknetInferenceService {
    /// Return the name of this service
    fn name(&self) -> &str {
        "Darknet Inference Service"
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
        let deserialized_input: DarknetInferenceService =
            match postcard::from_bytes(&input).map_err(|_| ErrNo::Canceled) {
                Ok(o) => o,
                Err(_) => return Ok(false),
            };
        *self = deserialized_input;
        Ok(true)
    }
}

impl DarknetInferenceService {
    /// Create a new service, with empty internal state.
    pub fn new() -> Self {
        Self {
            input_path: PathBuf::new(),
            cfg_path: PathBuf::new(),
            model_path: PathBuf::new(),
            labels_path: PathBuf::new(),
            output_path: PathBuf::new(),
        }
    }

    /// The core service. It loads the model pointed by `model_path` with the
    /// configuration in `cfg_path` and the labels defined in `labels_path`,
    /// then feeds the input read from `input_path` to the model, and writes the
    /// result to the file at `output_path`.
    fn infer(&mut self, fs: &mut FileSystem) -> FileSystemResult<()> {
        let DarknetInferenceService {
            input_path,
            cfg_path,
            model_path,
            labels_path,
            output_path,
        } = self;

        let input_file_paths: [&PathBuf; 4] = [input_path, cfg_path, labels_path, model_path];

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

        // Load network and labels
        let mut net =
            Network::load(cfg_path, Some(model_path), false).map_err(|_| ErrNo::Canceled)?;
        let object_labels = read_to_string(labels_path)?
            .lines()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        // Run inference
        let image = Image::open(input_path).map_err(|_| ErrNo::Canceled)?;
        let detections = net.predict(&image, 0.25, 0.5, 0.45, true);

        // Map detected objects to labels
        let objectness_threshold = 0.0;
        let mut labeled_detections: Vec<(usize, (Detection, f32, &String))> = detections
            .iter()
            .filter(|det| det.objectness() > objectness_threshold)
            .flat_map(|det| {
                det.best_class(None)
                    .map(|(class_index, prob)| (det, prob, &object_labels[class_index]))
            })
            .enumerate()
            .collect();

        // Sort labeled detections by descending probability
        labeled_detections.sort_by(|a, b| {
            let (_, (_, prob_a, _)) = a;
            let (_, (_, prob_b, _)) = b;
            if prob_b > prob_a {
                Ordering::Greater
            } else if prob_b < prob_a {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        });

        // Write result to output path
        let mut output = String::new();
        for (_, (detection, prob, label)) in labeled_detections {
            let BBox { x, y, w, h } = detection.bbox();
            write!(
                output,
                "{}\t{:.2}%\tx: {}\ty: {}\tw: {}\th: {}\n",
                label,
                prob * 100.0,
                x,
                y,
                w,
                h,
            )
            .map_err(|_| ErrNo::Canceled)?;
        }
        fs.write_file_by_absolute_path(
            Path::new("/").join(output_path),
            output.into_bytes(),
            true,
        )?;

        Ok(())
    }

    /// Reset the state, and erase the sensitive information.
    fn reset(&mut self) {
        self.input_path = PathBuf::new();
        self.cfg_path = PathBuf::new();
        self.model_path = PathBuf::new();
        self.labels_path = PathBuf::new();
        self.output_path = PathBuf::new();

        // Go back to work directory and delete files passed to the module and
        // created during execution
        set_current_dir(WORK_DIR.as_path()).unwrap();
        remove_dir_all(MODULE_DIR.as_path()).unwrap();
    }
}
