//! Data generator sdk/examples/image-processing
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.
//!
//! # Example
//! ```
//! cargo run -- --file_prefix [PREFIX_STRING] --width [WIDTH] --height [HEIGHT];
//! ```

use clap::{App, Arg};
use image::{imageops::FilterType, io::Reader, ImageFormat};
use std::error::Error;

/// Load a JPEG image from disk and save it to a *.dat, then convert it
/// to a PNG image of specific dimensions, under the same name.
/// Parameters:
/// * `file_prefix`, String, the prefix of the generated files.
/// * `width`, u64, the image width, default is 10.
/// * `height`, u64, the image height, default is 10.
fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for image processing")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Load a JPEG image and convert it to a PNG image of dimensions ([WIDTH], [HEIGHT])")
        .arg(
            Arg::with_name("file_prefix")
                .short("f")
                .long("file_prefix")
                .value_name("STRING")
                .help("The prefix for the output file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("image_path")
                .short("i")
                .long("image_path")
                .value_name("STRING")
                .help("The path to the JPEG image to load")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("width")
                .short("w")
                .long("width")
                .value_name("NUMBER")
                .help("The width of the image to generate")
                .takes_value(true)
                .validator(is_u64)
                .default_value("10"),
        )
        .arg(
            Arg::with_name("height")
                .short("h")
                .long("height")
                .value_name("NUMBER")
                .help("The height of the image to generate")
                .takes_value(true)
                .validator(is_u64)
                .default_value("10"),
        )
        .get_matches();

    let file_prefix = matches
        .value_of("file_prefix")
        .ok_or("Failed to read the file prefix.")?;
    let image_path = matches
        .value_of("image_path")
        .ok_or("Failed to read the image path.")?;
    let image_width = matches
        .value_of("width")
        .ok_or("Failed to read the width")?
        .parse::<u64>()
        .map_err(|_| "Failed to parse the width.")? as u32;
    let image_height = matches
        .value_of("height")
        .ok_or("Failed to read the height")?
        .parse::<u64>()
        .map_err(|_| "Failed to parse the height.")? as u32;

    let output_filename = format!("{}.dat", file_prefix);

    // Read PNG image
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
        .save_with_format(format!("{}", output_filename), ImageFormat::Png)
        .map_err(|e| format!("Failed to save image: {}", e));

    Ok(())
}

fn is_u64(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}
