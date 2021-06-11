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

use image::{GenericImageView, imageops, ImageFormat};

/// Read image from the virtual filesystem, crop the image, display the new dimensions and write
/// the new image to /output in PNG format.
/// By default, `jpeg-decode` reads JPEG images in parallel threads using `rayon`, which are not
/// supported in WASM. The workaround is to read PNG images instead
fn main() -> anyhow::Result<()> {
    // Use the open function to load an image from a Path.
    // `open` returns a `DynamicImage` on success.
    let mut img = image::open("/test.png")?;

    // Transform the image
    let subimg = imageops::crop(&mut img, 0, 0, 100, 100);
    println!("new dimensions: {:?}", subimg.dimensions());

    // Write the contents of this image to the Writer in PNG format.
    subimg.to_image().save_with_format("/output", ImageFormat::Png)?;

    Ok(())
}
