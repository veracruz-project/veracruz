//! Arm TrustZone platform-specific material.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod root_enclave_opcode;
pub mod runtime_manager_opcode;

pub fn transmute_from_u32(src: &[u32]) -> Vec<u8> {
    let mut dest: Vec<u8> = Vec::new();
    for this_value in src {
        dest.push(((this_value & 0xff000000) >> 24) as u8);
        dest.push(((this_value & 0x00ff0000) >> 16) as u8);
        dest.push(((this_value & 0x0000ff00) >> 8) as u8);
        dest.push((this_value & 0x000000ff) as u8);
    }
    return dest;
}

pub fn transmute_to_u32(src: &[u8]) -> Vec<u32> {
    let mut index = 0;
    let mut dest: Vec<u32> = Vec::new();
    while index < src.len() {
        let mut value:u32 = 0;
        value += (src[index] as u32) << 24;
        value += (src[index + 1] as u32) << 16;
        value += (src[index + 2] as u32) << 8;
        value += src[index + 3] as u32;
        index += 4;
        dest.push(value);
    }
    return dest;
}
