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

#[derive(Serialize, Debug)]
pub struct AesCtrInput {
    key: [u8; 16],
    iv: [u8; 16],
    input_path: PathBuf,
    output_path: PathBuf,
    is_encryption: bool,
}

fn main() -> anyhow::Result<()> {
    // Assume the key and iv are 128 bits.
    let mut key = [0u8; 16];
    read_exact_bytes("/input/key.dat", &mut key)?;
    let mut iv = [0u8; 16];
    read_exact_bytes("/input/iv.dat", &mut iv)?;
    let aes_ctr_input = AesCtrInput {
        key,
        iv,
        input_path: PathBuf::from("/input/data.dat"),
        output_path: PathBuf::from("/output/data.dat"),
        is_encryption: true,
    };
    println!("service input {:x?}", aes_ctr_input);
    let aes_ctr_input_bytes = postcard::to_allocvec(&aes_ctr_input)?;
    println!("prepare the bytes {:x?}", aes_ctr_input_bytes);
    write("/services/aesctr.dat", aes_ctr_input_bytes)?;
    println!("service returns");
    let result = read(aes_ctr_input.output_path)?;
    println!("result {:x?}", result);
    println!("service return");
    Ok(())
}

fn read_exact_bytes<T: AsRef<Path>>(path: T, buf: &mut [u8]) -> anyhow::Result<()> {
    let mut f = File::open(path)?;
    f.read_exact(buf)?;
    Ok(())
}
