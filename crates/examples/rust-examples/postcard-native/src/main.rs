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

use std::fs;
fn main() -> anyhow::Result<()> {
    let input = fs::read("/input/postcard.dat")?;
    fs::write("/services/postcard_string.dat", input)?;
    let rst = fs::read("/services/postcard_result.dat")?;
    fs::write("/output/postcard_native.txt", &rst)?;
    Ok(())
}
