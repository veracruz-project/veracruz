//! An example program to call the AES Counter mode native module.
//!
//! ## Context
//!
//! It calls the module mounted at path `/services/aesctr.dat`, via the postcard encoding of
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
//! See the file `LICENSE.md` in the Veracruz root directory for licensing
//! and copyright information.

use serde::Serialize;
use std::{
    fs::{read, write},
    path::PathBuf,
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
    let mut failed = false;

    // Assume the key and iv are 128 bits.
    let key: [u8; 16] = *b"aujourdhuimamane";
    let iv: [u8; 16] = *b"stmorteoupeutetr";
    let input = *b"ehierje";
    // printf ehierje > data.dat
    // openssl enc -aes-128-ctr -in data.dat -out enc.dat \
    //   -K $(printf aujourdhuimamane | od -An -tx1 | perl -pe 's/ //g;') \
    //   -iv $(printf stmorteoupeutetr | od -An -tx1 | perl -pe 's/ //g;') -p
    // od -An -tx1 enc.dat | perl -pe 's/ / 0x/g;'
    let expected_output = [0xa1, 0x20, 0x5e, 0x15, 0x7c, 0xf1, 0xb3];
    let aes_ctr_enc_input = AesCtrInput {
        key,
        iv,
        input_path: PathBuf::from("./output/data.dat"),
        output_path: PathBuf::from("./output/enc.dat"),
        is_encryption: true,
    };
    write(&aes_ctr_enc_input.input_path, input)?;
    let aes_ctr_enc_input_bytes = postcard::to_allocvec(&aes_ctr_enc_input)?;
    write("/tmp/aes/input", aes_ctr_enc_input_bytes)?;
    // wait the service finish
    let _ = read("/tmp/aes/output");
    let output = read(aes_ctr_enc_input.output_path)?;
    if output != expected_output {
        failed = true;
    }

    // Assume the key and iv are 128 bits.
    let key: [u8; 16] = *b"aujourdhuimamane";
    let iv: [u8; 16] = *b"stmorteoupeutetr";
    let input = *b"nesaispas";
    // printf nesaispas > data.dat
    // openssl enc -aes-128-ctr -in data.dat -out dec.dat \
    //   -K $(printf aujourdhuimamane | od -An -tx1 | perl -pe 's/ //g;') \
    //   -iv $(printf stmorteoupeutetr | od -An -tx1 | perl -pe 's/ //g;') -p
    // od -An -tx1 dec.dat | perl -pe 's/ / 0x/g;'
    let expected_output = [0xaa, 0x2d, 0x44, 0x11, 0x67, 0xe8, 0xa6, 0x2c, 0x9c];
    let aes_ctr_enc_input = AesCtrInput {
        key,
        iv,
        input_path: PathBuf::from("./output/data.dat"),
        output_path: PathBuf::from("./output/dec.dat"),
        is_encryption: false,
    };
    write(&aes_ctr_enc_input.input_path, input)?;
    let aes_ctr_enc_input_bytes = postcard::to_allocvec(&aes_ctr_enc_input)?;
    write("/tmp/aes/input", aes_ctr_enc_input_bytes)?;
    // wait the service finish
    let _ = read("/tmp/aes/output");
    let output = read(aes_ctr_enc_input.output_path)?;
    if output != expected_output {
        failed = true;
    }

    if !failed {
        write("./output/aesctr_native_pass.txt", [])?;
    }
    Ok(())
}
