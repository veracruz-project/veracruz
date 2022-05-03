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

use psa_crypto;
use psa_crypto::operations::hash;
use psa_crypto::types::algorithm::Hash;

/// Compute SHA-256 hash/digest.
pub fn sha256(x: &[u8]) -> Vec<u8> {
    psa_crypto::init().unwrap();
    let mut hash = vec![0; Hash::Sha256.hash_length()];
    hash::hash_compute(Hash::Sha256, &x, &mut hash).unwrap();
    hash
}
