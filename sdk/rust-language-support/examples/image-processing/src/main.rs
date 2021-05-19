//! A simple linear-regression example
//!
//! ## Context
//!
//! A relatively-low powered device (think e.g. an M-class microcontroller, or similar)
//! wants to offload some heavy, complex calculation to a third-party---here represented by a linear
//! regression problem.  The owner of the device wishes to ensure that the computation was
//! faithfully executed---that is, the results are trustworthy and are definitely the output of a
//! linear regression algorithm---and also are kept secret from third parties wishing to see what is
//! happening on the device.
//!
//! Inputs:                  1.
//! Assumed form of inputs:  one Pinecode-encoded `Vec<(f64, f64)>` representing a dataset of (x, y)
//!                          co-ordinates from which a linear relationship is to be extracted.
//! Ensured form of outputs: A Pinecode-encoded `LinearRegression` struct (see below) consisting of
//!                          a gradient and a Y-intercept, representing the best linear fit for the
//!                          input data.
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

use image::{GenericImageView, imageops};
use serde::Serialize;
use serde::Deserialize;
use std::{fs, process::exit, string::String, vec::Vec};
use std::error::Error;
use wasi_types::ErrNo;

/// Reads two input sources from the Veracruz host: the first input source is assumed to be a vector
/// of `AdvertisementViewer` structs, whilst the second is assumed to be a vector of `Customer`
/// structs.  Fails with [`return_code::ErrorCode::BadInput`] if the number of inputs provided is
/// not equal to 2, or if the inputs cannot be deserialized from Bincode.
/// TODO: read image directly (stream)
fn read_inputs() -> Result<Vec<String>, ErrNo> {
    let image = fs::read("/input-0")?;
    let image = pinecone::from_bytes(&image).map_err(|_| ErrNo::Proto)?;

    Ok(image)
}

//fn main() -> Result<(), Error> {
fn process_image() -> Result<(), wasi_types::ErrNo> {
    // Use the open function to load an image from a Path.
    // `open` returns a `DynamicImage` on success.
    let mut img = image::open("/test.jpg").map_err(|_|ErrNo::Proto)?;

    // The dimensions method returns the images width and height.
    fs::write("/output", format!("dimensions {:?}", img.dimensions()));

    // The color method returns the image's `ColorType`.
    fs::write("/output", format!("{:?}", img.color()));

    let subimg = imageops::crop(&mut img, 0, 0, 100, 100);

    // Write the contents of this image to the Writer in PNG format.
    subimg.to_image().save("/test.png").unwrap();

    fs::write("/output", "goodie")?;

    Ok(())
}

fn main() {
	if let Err(e) = process_image() {
		exit((e as u16).into());
	}
}
