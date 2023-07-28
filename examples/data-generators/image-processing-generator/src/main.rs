//! Data generator sdk/examples/image-processing
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright
//!
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
//! and copyright information.
//!
//! # Example
//! ```
//! cargo run -- --file_prefix [PREFIX_STRING] --width [WIDTH] --height [HEIGHT];
//! ```

use clap::Arg;
use image::{imageops::FilterType, io::Reader, ImageFormat};
use std::error::Error;

/// Load a JPEG image from disk and convert it to a PNG image of specific
/// dimensions, under the same name.
/// Parameters:
/// * `file_prefix`, String, the prefix of the generated files.
/// * `width`, u64, the image width, default is 10.
/// * `height`, u64, the image height, default is 10.
fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::Command::new("Data generator for image processing")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Load a JPEG image and convert it to a PNG image of dimensions ([WIDTH], [HEIGHT])")
        .arg(
            Arg::new("file_prefix")
                .short('f')
                .long("file_prefix")
                .value_name("STRING")
                .help("The prefix for the output file")
                .num_args(1)
                .required(true),
        )
        .arg(
            Arg::new("image_path")
                .short('i')
                .long("image_path")
                .value_name("STRING")
                .help("The path to the JPEG image to load")
                .num_args(1)
                .required(true),
        )
        .arg(
            Arg::new("width")
                .long("width")
                .value_name("NUMBER")
                .help("The width of the image to generate")
                .num_args(1)
                .value_parser(clap::value_parser!(u32))
                .default_value("10"),
        )
        .arg(
            Arg::new("height")
                .long("height")
                .value_name("NUMBER")
                .help("The height of the image to generate")
                .num_args(1)
                .value_parser(clap::value_parser!(u32))
                .default_value("10"),
        )
        .get_matches();

    let file_prefix = matches
        .get_one::<String>("file_prefix")
        .expect("Failed to read the file prefix.");
    let image_path = matches
        .get_one::<String>("image_path")
        .expect("Failed to read the image path.");
    let image_width = *matches
        .get_one::<u32>("width")
        .expect("Failed to read the width.");
    let image_height = *matches
        .get_one::<u32>("height")
        .expect("Failed to read the height.");

    let output_filename = format!("{}.png", file_prefix);

    // Read JPG image
    let mut reader =
        Reader::open(&image_path).map_err(|e| format!("Failed to open image: {}", e))?;
    reader.set_format(ImageFormat::Jpeg);
    let img = reader
        .decode()
        .map_err(|e| format!("Failed to load image: {}", e))?;

    // Resize image. Aspect ratio is not preserved
    let img = img.resize_exact(image_width, image_height, FilterType::Gaussian);

    // Save image as PNG.
    // This is required by the example, as `image` uses threads to load JPG images,
    // which are not supported in WebAssembly
    let _result = img
        .save_with_format(output_filename, ImageFormat::Png)
        .map_err(|e| format!("Failed to save image: {}", e));

    Ok(())
}
