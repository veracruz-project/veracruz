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
    prelude::SqliteConnection, update, Connection, ExpressionMethods, QueryDsl, RunQueryDsl,
};
use dotenv::dotenv;
use hex;
use models::NewDevice;
use schema::devices;
use schema::firmware_versions;
use std::env;

pub fn establish_connection() -> Result<SqliteConnection, ProxyAttestationServerError> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    Ok(SqliteConnection::establish(&database_url)?)
}

pub fn update_or_create_device<'a>(
    conn: &SqliteConnection,
    device_id: i32,
    pubkey_hash: &Vec<u8>,
    enclave_name: String,
) -> Result<(), ProxyAttestationServerError> {
    let encoded_hash = hex::encode(pubkey_hash);
    // first see if it already exists
    //let existing_device_id = devices::table.find(devices::addr.eq(addr)).select(devices::id).first(&conn).unwrap();
    let existing_device_id_result = devices::table
        .filter(devices::device_id.eq(device_id))
        .select(devices::id)
        .first::<i32>(conn);
    match existing_device_id_result {
        Ok(id) => {
            let _result = update(devices::table.find(id))
                .set(devices::pubkey_hash.eq(&encoded_hash))
                .execute(conn)?;
            //if result.is_err() {
            //return Err(format!("Failed to update existing device"));
            //}
            Ok(())
        }
        Err(_) => {
            // presume the error is "Not Found" TODO: Don't presume
            let new_device = NewDevice {
                device_id: device_id,
                pubkey_hash: encoded_hash,
                enclave_name: enclave_name,
            };

            let _result = diesel::insert_into(devices::table)
                .values(&new_device)
                .execute(conn)?;
            //if result.is_err() {
            //Err(format!("Failed to create new device:{:?}", result))
            //} else {
            Ok(())
            //}
        }
    }
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
