//! An example program to call the Darknet inference module.
//!
//! ## Context
//!
//! It calls the module mounted at path `/services/darknet_inference.dat` by
//! serializing a `DarknetInferenceInput` structure with postcard.
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

/// The interface with the Darknet inference service.
#[derive(Serialize, Debug)]
pub struct DarknetInferenceInput {
    /// Path to the input (image) to be fed to the network.
    input_path: PathBuf,
    /// Path to the model's configuration.
    cfg_path: PathBuf,
    /// Path to the actual model (weights).
    model_path: PathBuf,
    /// Path to the labels file containing all the objects that can be detected.
    labels_path: PathBuf,
    /// Path to the output file containing the result of the prediction.
    output_path: PathBuf,
    /// Threshold above which an object is considered detected.
    objectness_threshold: f32,
    /// Threshold above which a class is considered detected assuming objectness
    /// within the detection box. Darknet internally sets class probabilities to
    /// 0 if they are below the objectness threshold, so this should be above it
    /// to make any difference.
    class_threshold: f32,
    /// Hierarchical threshold. Only used in YOLO9000, a model able to detect
    /// hierarchised objects.
    hierarchical_threshold: f32,
    /// Intersection-over-union threshold. Used to eliminate irrelevant
    /// detection boxes.
    iou_threshold: f32,
    /// Whether the image should be letterboxed, i.e. padded while preserving
    /// its aspect ratio, or resized, before being fed to the model.
    letterbox: bool,
}

/// Example to invoke the Darknet inference service on a YOLO model.
/// Pass an image, a YOLO model with its configuration, various parameters and
/// a labels file to the service.
/// The prediction, a list of detected boxes, is written to `output_path`.
fn main() -> anyhow::Result<()> {
    let darknet_inference_input = DarknetInferenceInput {
        input_path: PathBuf::from("input/image.jpg"),
        cfg_path: PathBuf::from("input/yolov3.cfg"),
        model_path: PathBuf::from("input/yolov3.weights"),
        labels_path: PathBuf::from("input/coco.names"),
        output_path: PathBuf::from("output/prediction.log"),
        objectness_threshold: 0.25,
        class_threshold: 0.25,
        hierarchical_threshold: 0.5,
        iou_threshold: 0.45,
        letterbox: true,
    };
    println!("service input {:x?}", darknet_inference_input);

    let darknet_inference_input_bytes = postcard::to_allocvec(&darknet_inference_input)?;
    println!("calling Darknet Inference service...");
    write(
        "/services/darknet_inference.dat",
        darknet_inference_input_bytes,
    )?;
    let result = read_to_string(darknet_inference_input.output_path)?;
    println!("prediction:\n{:x?}", result);
    println!("service return");

    Ok(())
}
