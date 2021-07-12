//! The ORM data schema
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

table! {
    devices (id) {
        id -> Integer,
        device_id -> Integer,
        pubkey_hash -> Text,
        enclave_name -> Text,
    }
}

table! {
    firmware_versions (id) {
        id -> Integer,
        protocol -> Text,
        version_num -> Text,
        hash -> Text,
    }
}

allow_tables_to_appear_in_same_query!(devices, firmware_versions,);
