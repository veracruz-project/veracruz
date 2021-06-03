//! Platform generic material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::managers::RuntimeManagerError;

/// Break up a single array slice containing multiple certs, using the lengths in cert_lengths, into a 2D Vec
pub fn break_up_cert_array(cert_array: &[u8], cert_lengths: &[u32]) -> Result<std::vec::Vec<std::vec::Vec<u8>>, RuntimeManagerError> {

    let mut certs: std::vec::Vec<std::vec::Vec<u8> > = std::vec::Vec::new();

    let mut aggregate_length: usize = 0;
    // break the `cert_array` up according to the values in `certificate_lengths`
    // and place them in `certs`
    for this_length in cert_lengths.iter() {
        let mut this_cert: std::vec::Vec<u8> = vec![0; *this_length as usize];
        this_cert.copy_from_slice(&cert_array[aggregate_length..(aggregate_length + *this_length as usize)]);
        certs.push(this_cert);
        aggregate_length += *this_length as usize;
    }
    return Ok(certs);
}