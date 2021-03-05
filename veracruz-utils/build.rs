//! Veracruz utility build script
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "tz")]
use std::{env, fs, fs::File, io::Write, path::PathBuf};
#[cfg(feature = "tz")]
use uuid::Uuid;

fn main() {
    #[cfg(feature = "tz")]
    {
        let mc_uuid = match fs::read_to_string("../mexico_city_uuid.txt") {
            Ok(u) => u.trim().to_string(),
            Err(_) => {
                let u = Uuid::new_v4().to_string();
                fs::write("../mexico_city_uuid.txt", &u).unwrap();
                u
            }
        };
        let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
        let mut buffer = File::create(out.join("mexico_city_uuid.txt")).unwrap();
        write!(buffer, "{}", mc_uuid).unwrap();

        let root_enclave_uuid = match fs::read_to_string("../sgx-root-enclave-uuid.txt") {
            Ok(u) => u.trim().to_string(),
            Err(_) => {
                let u = Uuid::new_v4().to_string();
                fs::write("../sgx-root-enclave-uuid.txt", &u).unwrap();
                u
            }
        };
        let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
        let mut buffer = File::create(out.join("sgx-root-enclave-uuid.txt")).unwrap();
        write!(buffer, "{}", root_enclave_uuid).unwrap();
    }
}
