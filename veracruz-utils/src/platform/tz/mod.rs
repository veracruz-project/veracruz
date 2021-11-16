//! Arm TrustZone platform-specific material.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

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
        let mut value: u32 = 0;
        value += (src[index] as u32) << 24;
        value += (src[index + 1] as u32) << 16;
        value += (src[index + 2] as u32) << 8;
        value += src[index + 3] as u32;
        index += 4;
        dest.push(value);
    }
    return dest;
}

// Note: the following static value should not be a static value
// It should be the hash value of the current program, and it
// should be retrieved from the OS, not from itself (bootstrapping trust
// kinda doesn't work that way).
// However, OPTEE doesn't really provide this feature at the moment,
// therefore we've got this dirty hack here that COMPLETELY COMPROMISES
// the security of the system. THIS IS FOR DEMONSTRATION PURPOSES ONLY
// AND IS NOT SECURE IN ANY MEANINGFUL WAY!
pub static TRUSTZONE_RUNTIME_MANAGER_HASH: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe,
];
