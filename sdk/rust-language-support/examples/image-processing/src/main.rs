//! A simple image processing example
//!
//! ## Context
//!
//! A relatively-low powered device (think e.g. an M-class microcontroller, or similar)
//! wants to offload some heavy, complex calculation to a third-party---image processing here.
//! The owner of the device wishes to ensure that the computation was faithfully executed---that is,
//! the results are trustworthy and are definitely the output of the image transform---and also are
//! kept secret from third parties wishing to see what is happening on the device.
//!
//! Inputs:                  1.
//! Assumed form of inputs:  A PNG image mapped to the virtual filesystem at runtime
//! Ensured form of outputs: A PNG image mapped saved to the virtual filesystem
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

extern crate image;

use image::{GenericImageView, imageops, ImageFormat, io::Reader};
use std::process::exit;
use wasi_types::ErrNo;

/// Reads two input sources from the Veracruz host: the first input source is assumed to be a vector
/// of `AdvertisementViewer` structs, whilst the second is assumed to be a vector of `Customer`
/// structs.  Fails with [`return_code::ErrorCode::BadInput`] if the number of inputs provided is
/// not equal to 2, or if the inputs cannot be deserialized from Bincode.
/// TODO: read image directly (stream)

fn process_image() -> Result<(), wasi_types::ErrNo> {
    // Use the open function to load an image from a Path.
    // `open` returns a `DynamicImage` on success.
    // By default, jpeg-decode reads JPEG images in parallel threads (cf. rayon), which aren't supported in WASM. The workaround is to read PNG images instead
    let mut img = image::open("/test.png").map_err(|_| {
        println!("Failure opening /test.png");
        ErrNo::Proto
    })?;

    // Transform the image
    let subimg = imageops::crop(&mut img, 0, 0, 100, 100);
    println!("new dimensions: {:?}", subimg.dimensions());

    // Write the contents of this image to the Writer in PNG format.
    subimg.to_image().save_with_format("/output", ImageFormat::Png).unwrap();

    // Verify the output
    /*
    let img = Reader::open("/output").unwrap().with_guessed_format().unwrap().decode().unwrap();
    println!("dimensions {:?}", img.dimensions());
    println!("color type: {:?}", img.color());
    */

    Ok(())
}

fn main() {
	if let Err(e) = process_image() {
		exit((e as u16).into());
	}
}
