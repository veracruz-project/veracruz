//! The ORM library for the Veracruz proxy attestation server database
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod models;
pub mod schema;

use crate::error::ProxyAttestationServerError;
use diesel::{
    prelude::SqliteConnection, Connection, ExpressionMethods, QueryDsl, RunQueryDsl,
};
use dotenv::dotenv;
use hex;
use schema::devices;
use schema::firmware_versions;
use std::env;

pub fn establish_connection() -> Result<SqliteConnection, ProxyAttestationServerError> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    Ok(SqliteConnection::establish(&database_url)?)
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
