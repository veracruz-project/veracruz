//! Inference, using pre-trained Tensorflow models.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE.markdown` file in the Veracruz repository root directory
//! for licensing and copyright information.

use anyhow::{Context, Result};
use image::imageops::FilterType;
use image::{imageops::resize, load_from_memory_with_format, ImageFormat, RgbImage};
use pinecone::{from_bytes, to_vec};
use std::{fs::File, io::Read};
use tract_tensorflow::prelude::*;

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// Path to the pre-trained Tensorflow model.
const PRETRAINED_MODEL_PATH: &'static str = "/pretrained-tf-model";
/// Path to the bundle of input images.
const INPUT_IMAGES_PATH: &'static str = "/input-images";
/// Size (height) of the normalized input images.
const NORMALIZED_HEIGHT: uszie = 224;
/// Size (width) of the normalized input images.
const NORMALIZED_WIDTH: uszie = 224;

////////////////////////////////////////////////////////////////////////////////
// Loading inputs.
////////////////////////////////////////////////////////////////////////////////

/// Reads a pre-trained Tensorflow model from the virtual filesystem.
fn read_prebuilt_model() -> Result<InferenceModel> {
    tract_tensorflow::tensorflow()
        .model_for_path("PRETRAINED_MODEL_PATH")
        .context("Failed to load pre-trained Tensorflow model from virtual filesystem.")
}

/// Reads a (Pinecone-encoded) Vector of bytes that encode JPEG images from the
/// virtual filesystem.
fn read_images() -> Result<Vec<RgbImage>> {
    let mut raws = File::open(INPUT_IMAGES_PATH)
        .context("Failed to load input images from virtual filesystem.")?;

    let mut buffer = Vec::new();

    raws.read_to_end(&mut buffer)
        .context("Failed to read input images.")?;

    let deserialized: Vec<Vec<u8>> =
        from_bytes(&buffer).context("Failed to deserialize input images.")?;

    let mut result = Vec::new();

    for buffer in deserialized.iter() {
        let img = load_from_memory_with_format(buffer, ImageFormat::Jpeg)
            .context("Failed to load JPEG image from buffer.")?
            .to_rgb8();
        result.push(img);
    }

    Ok(result)
}

////////////////////////////////////////////////////////////////////////////////
// Inferencing.
////////////////////////////////////////////////////////////////////////////////

fn infer_image_content(model: &mut InferenceModel, image: &RgbImage) -> Result<()> {
    let resized = resize(
        image,
        NORMALIZED_WIDTH,
        NORMALIZED_HEIGHT,
        FilterType::Triangle,
    );

    let image: Tensor = tract_ndarray::Array4::from_shape_fn(
        (1, NORMALIZED_WIDTH, NORMALIZED_HEIGHT, 3),
        |(_, y, x, c)| resized[(x as _, y as _)][c] as f32 / 255.0,
    )
    .into();

    let model = model
        .with_input_fact(
            0,
            InferenceFact::dt_shape(
                f32::datum_type(),
                tvec!(1, NORMALIZED_WIDTH, NORMALIZED_HEIGHT, 3),
            ),
        )?
        .into_optimized()?
        .into_runnable()?;

    let output = model.run(tvec![])
}

fn main() -> Result<()> {
    let model = read_prebuilt_model()?;
    let images = read_images()?;
}
