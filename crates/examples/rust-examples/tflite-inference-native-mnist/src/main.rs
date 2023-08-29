//! An example program to call the TensorFlow Lite inference module on a MNIST
//! model, which can be downloaded at https://github.com/boncheolgu/tflite-rs/blob/master/data/MNISTnet_uint8_quant.tflite
//!
//! ## Context
//!
//! It calls the module mounted at path `/services/tflite_inference.dat` via a
//! `TfLiteInferenceInput` structure serialized with postcard.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for
//! licensing and copyright information.

use image::imageops;
use libc::c_int;
use serde::Serialize;
use std::{
    fs::{read, write},
    path::PathBuf,
};

/// The interface with the TensorFlow Lite inference service. This structure
/// should reflect the one expected by the native module, defined in
/// `tflite_inference.rs`
#[derive(Serialize, Debug)]
pub struct TfLiteInferenceInput {
    /// Path to the input tensor to be fed to the network.
    input_tensor_path: PathBuf,
    /// Path to the model serialized with FlatBuffers.
    model_path: PathBuf,
    /// Path to the output tensor containing the result of the prediction.
    output_tensor_path: PathBuf,
    /// Number of CPU threads to use for the TensorFlow Lite interpreter.
    num_threads: c_int,
}

const MNIST_MODEL_INPUT_SIZE: (u32, u32) = (28, 28);

/// Example to invoke the TensorFlow Lite inference service.
/// Pass a MNIST model, an input tensor encoding a handwritten digit as a
/// grayscale image, and additional configuration for the TensorFlow Lite
/// interpreter (number of threads), to the service.
/// The output tensor corresponding to the detection probability for each digit
/// is read from `output_tensor_path` and post-processed.
fn main() -> anyhow::Result<()> {
    // Read image of a handwritten digit. The digit must be white on a black
    // background
    let img = image::open("/input/digit.png")?;
    // Resize image to model's input size
    let img = imageops::resize(
        &img,
        MNIST_MODEL_INPUT_SIZE.0,
        MNIST_MODEL_INPUT_SIZE.1,
        imageops::FilterType::Triangle,
    );
    // Convert image to gray scale
    let img = imageops::colorops::grayscale(&img);
    let grayscale_image_binary = img.as_raw();
    write(
        "/program_internal/grayscale_image.bin",
        &grayscale_image_binary,
    )?;

    // Invoke service
    let tflite_inference_input = TfLiteInferenceInput {
        input_tensor_path: PathBuf::from("/program_internal/grayscale_image.bin"),
        model_path: PathBuf::from("/input/MNISTnet_uint8_quant.tflite"),
        output_tensor_path: PathBuf::from("/program_internal/output.dat"),
        num_threads: -1, // Let TF Lite pick how many threads it needs
    };
    println!("service input {:x?}", tflite_inference_input);
    let tflite_inference_input_bytes = postcard::to_allocvec(&tflite_inference_input)?;
    println!("calling TensorFlow Lite Inference service...");
    write(
        "/services/tflite_inference.dat",
        tflite_inference_input_bytes,
    )?;
    println!("service return");

    // Post-process results
    let result = read(tflite_inference_input.output_tensor_path)?;
    if result.len() != 10 {
        return Err(anyhow::anyhow!("Unexpected output size"));
    }
    let mut result_map = vec![];
    for i in 0..result.len() {
        let percentage = (result[i] as f32) * 100.0 / 255.0;
        result_map.push((i, percentage));
    }
    result_map.sort_by(|a, b| {
        if b.1 > a.1 {
            std::cmp::Ordering::Greater
        } else if b.1 < a.1 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    });
    println!("Detection probability per digit (descending):");
    for (i, percentage) in result_map {
        println!("{}: {:.2}%", i, percentage);
    }

    Ok(())
}
