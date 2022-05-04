//! Some simple manipulations of Distinguished Encoding Rules (DER).
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory
//! for information on licensing and copyright.

/// Convert a raw signature (64 bytes) into DER encoding:
/// two INTEGERs in a SEQUENCE.
pub fn sig_to_der(sig: Vec<u8>) -> Result<Vec<u8>, ()> {
    if sig.len() != 64 {
        Err(())
    } else {
        let x = &sig[0..32];
        let y = &sig[32..64];
        let xlen = 32 + x[0] / 128;
        let ylen = 32 + y[0] / 128;
        let mut r = vec![48, 4 + xlen + ylen];
        r.push(2);
        r.push(xlen);
        if xlen == 33 {
            r.push(0);
        }
        r.extend_from_slice(x);
        r.push(2);
        r.push(ylen);
        if ylen == 33 {
            r.push(0);
        }
        r.extend_from_slice(y);
        Ok(r)
    }
}

fn encode_der_length(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else {
        let mut der = vec![];
        let mut n = n;
        while n > 0 {
            der.push(n as u8);
            n /= 256
        }
        der.push(128 + der.len() as u8);
        der.reverse();
        der
    }
}

/// Extract DER length. Argument is updated to remaining input.
fn parse_der_length(der: &mut &[u8]) -> Result<usize, ()> {
    if der.len() < 1 || der[0] == 128 || der[0] == 255 {
        return Err(());
    }
    if der[0] < 128 {
        let len = der[0] as usize;
        *der = &der[1..];
        Ok(len)
    } else {
        let len_len = der[0] as usize - 128;
        if der.len() < 1 + len_len {
            return Err(());
        }
        let mut len = 0;
        for i in 1..(1 + len_len) {
            len = len * 256 + der[i] as usize;
        }
        *der = &der[(1 + len_len)..];
        return Ok(len);
    }
}

/// Extract DER tagged item with given ID. Second argument is updated
/// to remaining input. Return both the item and its contents.
fn parse_der<'a>(id: u8, der: &mut &'a [u8]) -> Result<(&'a [u8], &'a [u8]), ()> {
    if der.len() < 1 || der[0] != id {
        return Err(());
    }
    let mut rest = &der[1..];
    let length = parse_der_length(&mut rest)?;
    if rest.len() < length {
        return Err(());
    }
    let contents = &rest[0..length];
    rest = &rest[length..];
    let item = &der[0..(der.len() - rest.len())];
    *der = &rest;
    Ok((item, contents))
}

fn parse_der_item<'a>(id: u8, der: &mut &'a [u8]) -> Result<&'a [u8], ()> {
    let (item, _) = parse_der(id, der)?;
    Ok(item)
}

fn parse_der_contents<'a>(id: u8, der: &mut &'a [u8]) -> Result<&'a [u8], ()> {
    let (_, contents) = parse_der(id, der)?;
    Ok(contents)
}

/// Extract public key from private key in DER encoding.
pub fn extract_public(key: &[u8]) -> Result<Vec<u8>, ()> {
    let mut der = key;
    let mut seq = parse_der_contents(48, &mut der)?;
    if der != [] {
        return Err(());
    }
    let int0 = parse_der_contents(2, &mut seq)?;
    let int1 = parse_der_item(2, &mut seq)?;
    let int2 = parse_der_item(2, &mut seq)?;
    if int0 != [0] {
        return Err(());
    }
    let mut public = vec![48];
    public.extend_from_slice(&encode_der_length(int1.len() + int2.len()));
    public.extend_from_slice(int1);
    public.extend_from_slice(int2);
    Ok(public)
}

/// Convert a keypair (public, private) into a particular DER encoding.
pub fn keypair_to_der(raw_public: &[u8], raw_private: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if raw_public.len() != 65 || raw_private.len() != 32 {
        panic!(
            "Unexpected key size: {} {}",
            raw_public.len(),
            raw_private.len()
        )
    };
    let mut der_public = vec![3, 66, 0];
    der_public.extend_from_slice(&raw_public);

    let mut der_private = vec![
        48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206,
        61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32,
    ];
    der_private.extend_from_slice(&raw_private);
    der_private.extend_from_slice(vec![161, 68].as_slice());
    der_private.extend_from_slice(der_public.as_slice());
    (der_public, der_private)
}

/// This is the crazy way we extract a keypair from an enclave key.
pub fn extract_keys_from_enclave_key(key: &[u8]) -> (&[u8], &[u8]) {
    (&key[73..138], &key[36..68])
}
