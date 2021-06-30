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
use downloader::{Download, Downloader};
use image::{io::Reader, ImageFormat};
use std::{error::Error, path::Path};

/// Download a random JPEG image from https://picsum.photos/ and save it in a *.dat, then convert it
/// to a PNG image under the same name.
/// Parameters:
/// * `file_prefix`, String, the prefix of the generated files.
/// * `width`, u64, the image width, default is 10.
/// * `height`, u64, the image height, default is 10.
fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Data generator for image processing")
        .version("pre-alpha")
        .author("The Veracruz Development Team")
        .about("Download a random JPEG image of dimensions ([WIDTH], [HEIGHT]) and convert it to a PNG image") 
       .arg(
           Arg::with_name("file_prefix")
               .short("f")
               .long("file_prefix")
               .value_name("STRING")
               .help("The prefix for the output file")
               .takes_value(true)
               .required(true)
       )
       .arg(
           Arg::with_name("width")
               .short("w")
               .long("width")
               .value_name("NUMBER")
               .help("The width of the image to generate")
               .takes_value(true)
               .validator(is_u64)
               .default_value("10")
       )
       .arg(
           Arg::with_name("height")
               .short("h")
               .long("height")
               .value_name("NUMBER")
               .help("The height of the image to generate")
               .takes_value(true)
               .validator(is_u64)
               .default_value("10")
       )
       .arg(
           Arg::with_name("seed")
               .short("e")
               .long("seed")
               .value_name("NUBMER")
               .help("The seed for the random number generator.")
               .takes_value(true)
               .validator(is_u64)
               .default_value("0"),
        )
        .get_matches();

    let file_prefix = matches
        .value_of("file_prefix")
        .ok_or("Failed to read the file prefix.")?;
    let image_width = matches
        .value_of("width")
        .ok_or("Failed to read the width")?;
    let image_height = matches
        .value_of("height")
        .ok_or("Failed to read the height")?;

    // Download random image
    let mut downloader = Downloader::builder()
        .download_folder(std::path::Path::new("./"))
        .parallel_requests(1)
        .build()
        .expect("Failed to configure the downloader");
    let file_path = format!("{}.dat", file_prefix);
    let dl =
        Download::new(format!("https://picsum.photos/{}/{}", image_width, image_height).as_str())
            .file_name(Path::new(&file_path));
    let _result = downloader
        .download(&[dl])
        .map_err(|e| format!("Failed to download image: {}", e));

    // Convert image to PNG.
    // This is required by the example, as `image` uses threads to load JPG images, which are not supported in WebAssembly
    let mut reader =
        Reader::open(&file_path).map_err(|e| format!("Failed to open image: {}", e))?;
    reader.set_format(ImageFormat::Jpeg);
    let img = reader
        .decode()
        .map_err(|e| format!("Failed to load image: {}", e))?;
    let _result = img
        .save_with_format(file_path, ImageFormat::Png)
        .map_err(|e| format!("Failed to save image: {}", e));

    Ok(())
}

fn is_u64(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Cannot parse {} to u64, with error {:?}", v, e)),
    }
}
