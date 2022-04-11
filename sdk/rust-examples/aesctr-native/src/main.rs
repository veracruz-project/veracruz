//! An example program to call the AES Counter mode native module.
//!
//! ## Context
//!
//! It calls the module mounted at path `/services/postcard_string.dat`. It is expected to
//! deserialize the postcard encoding of a made-up type and serialize to JSON string.
//! The result is written to `/services/postcard_result.dat`.
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
pub struct AesCtrInput {
    key: [u8; 16],
    iv: [u8; 16],
    input_path: PathBuf,
    output_path: PathBuf,
    is_encryption: bool,
}

/// Example to invoke the Counter mode AES service. Encrypt `data.dat` and then 
/// decrypt it using the `key.dat` and iv.dat`.
fn main() -> anyhow::Result<()> {
    // Assume the key and iv are 128 bits.
    let mut key = [0u8; 16];
    read_exact_bytes("/input/key.dat", &mut key)?;
    let mut iv = [0u8; 16];
    read_exact_bytes("/input/iv.dat", &mut iv)?;
    let aes_ctr_enc_input = AesCtrInput {
        key,
        iv,
        input_path: PathBuf::from("/input/data.dat"),
        output_path: PathBuf::from("/output/enc.dat"),
        is_encryption: true,
    };
    let result = read(&aes_ctr_enc_input.input_path)?;
    println!("data input {:x?}", result);
    println!("service enc input {:x?}", aes_ctr_enc_input);
    let aes_ctr_enc_input_bytes = postcard::to_allocvec(&aes_ctr_enc_input)?;
    println!("prepare the enc bytes {:x?}", aes_ctr_enc_input_bytes);
    write("/services/aesctr.dat", aes_ctr_enc_input_bytes)?;
    let result = read(aes_ctr_enc_input.output_path)?;
    println!("enc result {:x?}", result);
    let aes_ctr_dec_input = AesCtrInput {
        key,
        iv,
        input_path: PathBuf::from("/output/enc.dat"),
        output_path: PathBuf::from("/output/dec.dat"),
        is_encryption: false,
    };
    let aes_ctr_dec_input_bytes = postcard::to_allocvec(&aes_ctr_dec_input)?;
    println!("prepare the enc bytes {:x?}", aes_ctr_dec_input_bytes);
    write("/services/aesctr.dat", aes_ctr_dec_input_bytes)?;
    let result = read(aes_ctr_dec_input.output_path)?;
    println!("dec result {:x?}", result);
    println!("service return");
    Ok(())
}

fn read_exact_bytes<T: AsRef<Path>>(path: T, buf: &mut [u8]) -> anyhow::Result<()> {
    let mut f = File::open(path)?;
    f.read_exact(buf)?;
    Ok(())
}
