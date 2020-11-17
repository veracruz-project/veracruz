//! Buffer for program and data.
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use err_derive::Error;
use std::{collections::HashMap, result::Result, vec::Vec};

type ClientID = u64;
type PackageID = u64;
type DataPackage = chihuahua::hcall::common::DataSourceMetadata;

/// Error type for mexico-city buffer.
#[derive(Clone, Debug, Error)]
pub enum MexicoCityBufferError {
    /// There is already a buffered program.
    #[error(display = "Already have a buffered program.")]
    AlreadyHaveBufferedProgram,
    /// Duplicated (static) data package.
    #[error(
        display = "Already have a data package from client {} with id {}.",
        client_id,
        package_id
    )]
    AlreadyHaveBufferedData {
        client_id: ClientID,
        package_id: PackageID,
    },
    /// Duplicated stream package.
    #[error(
        display = "Already have a stream package from client {} with id {}.",
        client_id,
        package_id
    )]
    AlreadyHaveBufferedStream {
        client_id: ClientID,
        package_id: PackageID,
    },
    /// No buffered program.
    #[error(display = "There is no buffered program.")]
    NoBufferedProgram,
    /// No buffered (static) data.
    #[error(
        display = "There is no buffered data package from client {} with id {}.",
        client_id,
        package_id
    )]
    NoBufferedData {
        client_id: ClientID,
        package_id: PackageID,
    },
    /// No buffered (static) data.
    #[error(
        display = "There is no buffered stream package from client {} with id {}.",
        client_id,
        package_id
    )]
    NoBufferedStream {
        client_id: ClientID,
        package_id: PackageID,
    },
}

/// Buffer for storing program, (static) data, and stream data.
pub(crate) struct MexicoCityBuffer {
    // Program in binary form, initially None.
    program: Option<Vec<u8>>,
    // All initial data indexed by ClientID and then PackageID, that is availalble in each stream round.
    data: HashMap<ClientID, HashMap<PackageID, DataPackage>>,
    // All streaming data, indexed by ClientID, then by PackageID
    stream: HashMap<ClientID, HashMap<PackageID, DataPackage>>,
}

impl MexicoCityBuffer {
    /// Initialize a new empty buffer.
    pub(crate) fn new() -> Self {
        MexicoCityBuffer {
            program: None,
            data: HashMap::new(),
            stream: HashMap::new(),
        }
    }

    /// Buffer a program. Raise an error if there is already a program.
    pub(crate) fn buffer_program(&mut self, prog: &[u8]) -> Result<(), MexicoCityBufferError> {
        if self.program.is_some() {
            Err(MexicoCityBufferError::AlreadyHaveBufferedProgram)
        } else {
            self.program = Some(prog.to_vec());
            Ok(())
        }
    }

    /// Buffer a (static) data package. Raise an error if it is a duplicated data package.
    pub(crate) fn buffer_data(
        &mut self,
        package: &DataPackage,
    ) -> Result<(), MexicoCityBufferError> {
        let client_id = package.get_client_id();
        let package_id = package.get_package_id();
        if Self::buffer_package(&mut self.data, package) {
            Ok(())
        } else {
            Err(MexicoCityBufferError::AlreadyHaveBufferedData {
                client_id,
                package_id,
            })
        }
    }

    /// Buffer a stream data package. Raise an error if it is a duplicated stream package.
    pub(crate) fn buffer_stream(
        &mut self,
        package: &DataPackage,
    ) -> Result<(), MexicoCityBufferError> {
        let client_id = package.get_client_id();
        let package_id = package.get_package_id();
        if Self::buffer_package(&mut self.stream, package) {
            Ok(())
        } else {
            Err(MexicoCityBufferError::AlreadyHaveBufferedStream {
                client_id,
                package_id,
            })
        }
    }

    /// Add the data package into `buffer` and return true if it does not exist, otherwise false.
    fn buffer_package(
        buffer: &mut HashMap<ClientID, HashMap<PackageID, DataPackage>>,
        package: &DataPackage,
    ) -> bool {
        let client_id = package.get_client_id();
        let package_id = package.get_package_id();
        if !buffer.contains_key(&client_id) {
            buffer.insert(client_id, HashMap::new());
        }
        buffer
            .get_mut(&client_id)
            .map(|l| {
                if l.contains_key(&package_id) {
                    // a package exists
                    false
                } else {
                    l.insert(package_id, package.clone());
                    true
                }
            })
            // default is false in case, that is, `failure` state.
            .unwrap_or(false)
    }

    /// Assume there is buffered program, otherwise return error
    pub(crate) fn get_program(&self) -> Result<&[u8], MexicoCityBufferError> {
        self.program
            .as_ref()
            .map(|l| l.as_slice())
            .ok_or(MexicoCityBufferError::NoBufferedProgram)
    }

    /// Fetch a buffered (static) data of a client and a package ID.
    /// Return an error if the data does not exist.
    pub(crate) fn get_data(
        &self,
        client_id: ClientID,
        package_id: PackageID,
    ) -> Result<&DataPackage, MexicoCityBufferError> {
        Self::get_package(&self.data, client_id, package_id).ok_or(
            MexicoCityBufferError::NoBufferedData {
                client_id,
                package_id,
            },
        )
    }

    /// Fetch all (static) data packages
    pub(crate) fn all_data(&self) -> Result<Vec<DataPackage>, MexicoCityBufferError> {
        Ok(self
            .data
            .values()
            .map(|l| l.values().map(|m| m.clone()).collect::<Vec<DataPackage>>())
            .collect::<Vec<Vec<DataPackage>>>()
            .concat())
    }

    /// Fetch a buffered stream data of a client and a package ID.
    /// Return an error if the data does not exist.
    pub(crate) fn get_stream(
        &self,
        client_id: ClientID,
        package_id: PackageID,
    ) -> Result<&DataPackage, MexicoCityBufferError> {
        Self::get_package(&self.data, client_id, package_id).ok_or(
            MexicoCityBufferError::NoBufferedStream {
                client_id,
                package_id,
            },
        )
    }

    /// Fetch the buffered package. If the package does not exist, return None.
    fn get_package(
        buffer: &HashMap<ClientID, HashMap<PackageID, DataPackage>>,
        client_id: ClientID,
        package_id: PackageID,
    ) -> Option<&DataPackage> {
        buffer.get(&client_id).map(|l| l.get(&package_id)).flatten()
    }
}
