//! SHA256 function.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory
//! for information on licensing and copyright.

use mbedtls::hash::{Md, Type};

/// Compute SHA-256 hash/digest.
pub fn sha256(x: &[u8]) -> Vec<u8> {
    const HASH_SIZE: usize = 32;
    let mut out: [u8; HASH_SIZE] = [0; HASH_SIZE];
    let n = Md::hash(Type::Sha256, x, &mut out);
    if n.is_err() || n.unwrap() != HASH_SIZE {
        panic!("bad sha256")
    }
    out.to_vec()
}
