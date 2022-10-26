//! An example program to call the Darknet inference module.
//!
//! ## Context
//!
//! It calls the module mounted at path `/services/darknet_inference.dat`, via
//! the postcard encoding of the interface,
//! ```
//! pub struct DarknetInferenceInput {
//!     input_path: PathBuf,
//!     cfg_path: PathBuf,
//!     model_path: PathBuf,
//!     labels_path: PathBuf,
//!     output_path: PathBuf,
//! }
//! ```
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use serde::Serialize;
use std::{
    fs::{read_to_string, write},
    path::PathBuf,
};

/// The interface with the Darknet inference service
#[derive(Serialize, Debug)]
pub struct DarknetInferenceInput {
    input_path: PathBuf,
    cfg_path: PathBuf,
    model_path: PathBuf,
    labels_path: PathBuf,
    output_path: PathBuf,
}

/// Example to invoke the Darknet inference service.
/// Pass an image, a YOLO model with its configuration and a labels file to the
/// service.
/// The prediction is written to `output_path`
fn main() -> anyhow::Result<()> {
    let darknet_inference_input = DarknetInferenceInput {
        input_path: PathBuf::from("input/image.jpg"),
        cfg_path: PathBuf::from("input/yolov3-tiny.cfg"),
        model_path: PathBuf::from("input/yolov3-tiny.weights"),
        labels_path: PathBuf::from("input/coco.names"),
        output_path: PathBuf::from("output/prediction.dat"),
    };
    println!("service input {:x?}", darknet_inference_input);

    let darknet_inference_input_bytes = postcard::to_allocvec(&darknet_inference_input)?;
    println!("calling Darknet Inference service...");
    write("/services/darknet_inference.dat", darknet_inference_input_bytes)?;
    let result = read_to_string(darknet_inference_input.output_path)?;
    println!("prediction:\n{:x?}", result);
    println!("service return");

    Ok(())
}
