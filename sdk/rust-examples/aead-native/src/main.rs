//! An example to call a native module.
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

use std::fs;

const KEY_DATA: [u8; 16] = [
    0x41, 0x89, 0x35, 0x1B, 0x5C, 0xAE, 0xA3, 0x75, 0xA0, 0x29, 0x9E, 0x81, 0xC6, 0x21, 0xBF, 0x43,
];
const NONCE: [u8; 13] = [
    0x48, 0xc0, 0x90, 0x69, 0x30, 0x56, 0x1e, 0x0a, 0xb0, 0xef, 0x4c, 0xd9, 0x72,
];

const DECRYPTED_DATA: [u8; 24] = [
    0x45, 0x35, 0xd1, 0x2b, 0x43, 0x77, 0x92, 0x8a, 0x7c, 0x0a, 0x61, 0xc9, 0xf8, 0x25, 0xa4, 0x86,
    0x71, 0xea, 0x05, 0x91, 0x07, 0x48, 0xc8, 0xef,
];

fn main() -> anyhow::Result<()> {
    let input_output_path = "/output/data.dat";
    fs::write(input_output_path, DECRYPTED_DATA)?;
    println!("write the data.dat");
    let service_input = [&KEY_DATA as &[_], &NONCE, input_output_path.as_bytes(), &[0u8]].concat();
    println!("prepare the bytes {:x?}", service_input);
    fs::write("/services/aead.dat", service_input)?;
    let result = fs::read(input_output_path)?;
    println!("result {:x?}", result);
    println!("service return");
    Ok(())
}
