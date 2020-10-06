use err_derive::Error;
use std::{collections::HashMap, result::Result, vec::Vec};

type ClientID = u64;
type PackageID = u64;
type DataPackage = chihuahua::hcall::common::DataSourceMetadata;
//pub struct DataSourceMetadata {
///// The raw data (encoded in bytes) provisioned into the enclave.
//pub data: Vec<u8>,
///// Who provisioned this data.
//pub client_id: u64,
//pub package_id: u64,
//}

// TODO: ERROR might propagate outside of this crate?
#[derive(Clone, Debug, Error)]
pub enum MexicoCityBufferError {
    #[error(display = "Already have a buffered program.")]
    AlreadyHaveBufferedProgram,
    #[error(
        display = "Already have a data package from client {} with id {}.",
        client_id,
        package_id
    )]
    AlreadyHaveBufferedData {
        client_id: ClientID,
        package_id: PackageID,
    },
    #[error(
        display = "Already have a stream package from client {} with id {}.",
        client_id,
        package_id
    )]
    AlreadyHaveBufferedStream {
        client_id: ClientID,
        package_id: PackageID,
    },
    #[error(display = "There is no buffered program.")]
    NoBufferedProgram,
    #[error(
        display = "There is no buffered data package from client {} with id {}.",
        client_id,
        package_id
    )]
    NoBufferedData {
        client_id: ClientID,
        package_id: PackageID,
    },
}

pub(crate) struct MexicoCityBuffer {
    // Program in binary form, initially None.
    program: Option<Vec<u8>>,
    // All initial data indexed by ClientID and then PackageID, that is availalble in each stream round.
    data: HashMap<ClientID, HashMap<PackageID, DataPackage>>,
    // All streaming data, indexed by ClientID, then by PackageID
    stream: HashMap<ClientID, HashMap<PackageID, DataPackage>>,
}

impl MexicoCityBuffer {
    pub(crate) fn new() -> Self {
        MexicoCityBuffer {
            program: None,
            data: HashMap::new(),
            stream: HashMap::new(),
        }
    }

    pub(crate) fn buffer_program(&mut self, prog: &[u8]) -> Result<(), MexicoCityBufferError> {
        if self.program.is_some() {
            Err(MexicoCityBufferError::AlreadyHaveBufferedProgram)
        } else {
            self.program = Some(prog.to_vec());
            Ok(())
        }
    }

    pub(crate) fn buffer_data(
        &mut self,
        package: &DataPackage,
    ) -> Result<(), MexicoCityBufferError> {
        let &DataPackage {
            client_id,
            package_id,
            ..
        } = package;
        if Self::buffer_package(&mut self.data, package) {
            Ok(())
        } else {
            Err(MexicoCityBufferError::AlreadyHaveBufferedData {
                client_id,
                package_id,
            })
        }
    }

    pub(crate) fn buffer_stream(
        &mut self,
        package: &DataPackage,
    ) -> Result<(), MexicoCityBufferError> {
        let &DataPackage {
            client_id,
            package_id,
            ..
        } = package;
        if Self::buffer_package(&mut self.stream, package) {
            Ok(())
        } else {
            Err(MexicoCityBufferError::AlreadyHaveBufferedStream {
                client_id,
                package_id,
            })
        }
    }

    // Add the data package into buffer and return true if it does not exist, otherwise false
    fn buffer_package(
        buffer: &mut HashMap<ClientID, HashMap<PackageID, DataPackage>>,
        package: &DataPackage,
    ) -> bool {
        let &DataPackage {
            client_id,
            package_id,
            ..
        } = package;
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

    /// Fetch all (initial) data packages
    pub(crate) fn all_data(&self) -> Result<Vec<DataPackage>, MexicoCityBufferError> {
        Ok(self
            .data
            .values()
            .map(|l| l.values().map(|m| m.clone()).collect::<Vec<DataPackage>>())
            .collect::<Vec<Vec<DataPackage>>>()
            .concat())
    }

    pub(crate) fn get_stream(
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

    // Fetch the buffered package. If the package does not exist, return None.
    fn get_package(
        buffer: &HashMap<ClientID, HashMap<PackageID, DataPackage>>,
        client_id: ClientID,
        package_id: PackageID,
    ) -> Option<&DataPackage> {
        buffer.get(&client_id).map(|l| l.get(&package_id)).flatten()
    }
}
