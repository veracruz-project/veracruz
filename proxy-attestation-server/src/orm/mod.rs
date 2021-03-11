//! The ORM library for the Veracruz proxy attestation server database
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod models;
pub mod schema;

use crate::error::ProxyAttestationServerError;
use diesel::{
    prelude::SqliteConnection, Connection, ExpressionMethods, QueryDsl, RunQueryDsl,
};
use diesel_migrations;
use diesel_migrations::MigrationConnection;
use dotenv::dotenv;
use hex;
use models::NewDevice;
use models::FirmwareVersion;
use schema::devices;
use schema::firmware_versions;
use std::env;

// Embed migrations in our binary
diesel_migrations::embed_migrations!("migrations");

pub fn establish_connection() -> Result<SqliteConnection, ProxyAttestationServerError> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let conn = SqliteConnection::establish(&database_url)?;

    // check if our firmware_versions table exists, if it doesn't we assume
    // we need to migrate and setup the database
    if !diesel::dsl::select(
        diesel::dsl::exists(
            firmware_versions::table
                .select(firmware_versions::id)
        )
    ).get_result(&conn).unwrap_or(false) {
        // ensure our db is migrated
        embedded_migrations::run_with_output(&conn, &mut std::io::stdout())?;

        #[allow(dead_code)]
        let mut id = 0;

        // populate with firmware versions
        #[cfg(feature = "sgx")]
        {
            id += 1;
            diesel::insert_into(firmware_versions::table)
                .values(&FirmwareVersion {
                    id: id,
                    protocol: "sgx".to_string(),
                    version_num: env!("SGX_FIRMWARE_VERSION").to_string(),
                    hash: env!("SGX_FIRMWARE_HASH").to_string(),
                })
                .execute(&conn)?;
        }

        // populate with firmware versions
        #[cfg(feature = "psa")]
        {
            id += 1;
            diesel::insert_into(firmware_versions::table)
                .values(&FirmwareVersion {
                    id: id,
                    protocol: "psa".to_string(),
                    version_num: env!("PSA_FIRMWARE_VERSION").to_string(),
                    hash: env!("PSA_FIRMWARE_HASH").to_string(),
                })
                .execute(&conn)?;
        }
    
        // populate with firmware versions
        #[cfg(feature = "nitro")]
        {
            id += 1;
            diesel::insert_into(firmware_versions::table)
                .values(&FirmwareVersion {
                    id: id,
                    protocol: "nitro".to_string(),
                    version_num: env!("NITRO_FIRMWARE_VERSION").to_string(),
                    hash: env!("NITRO_FIRMWARE_HASH").to_string(),
                })
                .execute(&conn)?;
        }
    }

    Ok(conn)
}

pub fn query_device<'a>(conn: &SqliteConnection, device_id: i32) -> Result<Vec<u8>, ProxyAttestationServerError> {
    let hashes: Vec<String> = devices::table
        .filter(devices::device_id.eq(device_id))
        .select(devices::pubkey_hash)
        .load(conn)?;
    let pubkey_hash_vec = hex::decode(hashes[0].to_owned())?;
    Ok(pubkey_hash_vec)
}

pub fn get_firmware_version_hash<'a>(
    conn: &SqliteConnection,
    protocol: &String,
    version: &String,
) -> Result<Option<Vec<u8>>, ProxyAttestationServerError> {
    let hashes: Vec<String> = firmware_versions::table
        .filter(firmware_versions::protocol.eq(protocol))
        .filter(firmware_versions::version_num.eq(version))
        .select(firmware_versions::hash)
        .load(conn)
            .map_err(|err| {
                println!("proxy-attestation-server::orm::get_firmware_version_hash failed to query table:{:?}", err);
                err
            })?;

    let hash_vec = hex::decode(hashes[0].to_owned())
        .map_err(|err| {
            println!("proxy-attestation-server::orm::get_firmware_version_hash failed to decode contents:{:?}", err);
            err
        })?;

    Ok(Some(hash_vec))
}
