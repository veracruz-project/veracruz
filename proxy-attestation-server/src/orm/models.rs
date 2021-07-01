//! The ORM data model
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::schema::firmware_versions;

#[derive(Queryable, Associations, Debug, Identifiable, AsChangeset)]
#[table_name = "firmware_versions"]
pub struct FirmwareVersion {
    pub id: i32,
    pub protocol: String,
    pub version_num: String,
    pub hash: String,
}
