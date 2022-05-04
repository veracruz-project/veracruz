//! ECDSA functions.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory
//! for information on licensing and copyright.

use crate::der;
use crate::sha256::sha256;
use psa_crypto;
use psa_crypto::operations::asym_signature;
use psa_crypto::operations::key_management;
use psa_crypto::types::algorithm::{AsymmetricSignature, Hash};
use psa_crypto::types::key::{Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags};

/// Attributes for exportable ECDSA key for signing.
fn attributes() -> Attributes {
    let mut usage_flags: UsageFlags = Default::default();
    usage_flags.set_sign_hash().set_export();
    Attributes {
        // ECDST prime256v1 = secp256r1 = P-256
        key_type: Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        bits: 256,
        lifetime: Lifetime::Volatile,
        policy: Policy {
            usage_flags,
            permitted_algorithms: AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }
            .into(),
        },
    }
}

/// Generate ECDSA keypair (public, private) in DER encoding.
pub fn generate() -> (Vec<u8>, Vec<u8>) {
    psa_crypto::init().unwrap();
    let attributes = attributes();
    let key = key_management::generate(attributes, None).unwrap();
    let mut public = vec![0; attributes.export_public_key_output_size().unwrap()];
    let mut private = vec![0; attributes.export_key_output_size().unwrap()];
    let size = key_management::export_public(key, &mut public).unwrap();
    public.resize(size, 0);
    let size = key_management::export(key, &mut private).unwrap();
    private.resize(size, 0);
    unsafe { key_management::destroy(key) }.unwrap();
    der::keypair_to_der(&public, &private)
}

/// Create ECDSA signature in DER encoding.
pub fn sign(_public: &[u8], private: &[u8], data: &[u8]) -> Vec<u8> {
    let hash = sha256(&data);
    psa_crypto::init().unwrap();
    let attributes = attributes();
    let key = key_management::import(attributes, None, &private).unwrap();
    let alg = AsymmetricSignature::Ecdsa {
        hash_alg: Hash::Sha256.into(),
    };
    let mut signature = vec![0; attributes.sign_output_size(alg).unwrap()];
    let size = asym_signature::sign_hash(key, alg, &hash, &mut signature).unwrap();
    signature.resize(size, 0);
    unsafe { key_management::destroy(key) }.unwrap();
    der::sig_to_der(signature).unwrap()
}
