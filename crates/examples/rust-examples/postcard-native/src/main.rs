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
//! See the file `LICENSE.md` in the Veracruz root directory for licensing
//! and copyright information.

use std::fs::{read, write};

fn main() -> anyhow::Result<()> {
    let input = read("./input/postcard.dat")?;
    write("/tmp/postcard/input", input)?;
    let rst = read("/tmp/postcard/output")?;
    write("./output/postcard_native.txt", &rst)?;
    Ok(())
}
