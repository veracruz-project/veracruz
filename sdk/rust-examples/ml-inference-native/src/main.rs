//! An example program to call the Machine Learning Inference module.
//!
//! ## Context
//!
//! It calls the module mounted at path `/services/mlinf.dat`, via the postcard encoding of
//! the interface,
//! ```
//! pub struct AesCtrInput {
//!     key: [u8; 16],
//!     iv: [u8; 16],
//!     input_path: PathBuf,
//!     output_path: PathBuf,
//!     is_encryption: bool,
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
    fs::{read, write, File},
    io::Read,
    path::{Path, PathBuf},
};

/// The interface between Counter mode AES service
#[derive(Serialize, Debug)]
pub struct MlInferenceInput {
    input_path: PathBuf,
    model_path: PathBuf,
    output_path: PathBuf,
}

/// Example to invoke the Counter mode AES service. Encrypt `data.dat` and then 
/// decrypt it using the `key.dat` and iv.dat`.
fn main() -> anyhow::Result<()> {
    println!("main");
    let ml_inference_input = MlInferenceInput {
        input_path: PathBuf::from("/input/data.dat"),
        model_path: PathBuf::from("/input/model.weights"),
        output_path: PathBuf::from("/output/prediction.dat"),
    };
    std::process::exit(0);
    let result = read(&ml_inference_input.input_path)?;
    println!("data input {:x?}", result);
    println!("service input {:x?}", ml_inference_input);
    let ml_inference_input_bytes = postcard::to_allocvec(&ml_inference_input)?;
    println!("prepare the enc bytes {:x?}", ml_inference_input_bytes);
    write("/services/mlinf.dat", ml_inference_input_bytes)?;
    let result = read(ml_inference_input.output_path)?;
    println!("prediction result {:x?}", result);
    println!("service return");
    Ok(())
}
