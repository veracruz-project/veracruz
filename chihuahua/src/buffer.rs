///! GLUE CODE FOR NEW API.
///! IT SHOULD BE REPLACED BY FS IMPLEMENTATION.

use err_derive::Error;
use std::{collections::HashMap, result::Result, vec::Vec, string::String};
use veracruz_utils::{VeracruzCapabilityIndex, VeracruzCapability, VeracruzCapabilityTable};

/// Error type for mexico-city buffer.
#[derive(Clone, Debug, Error)]
pub enum FileSystemError {
    //TODO: potential remove this 
    #[error(
        display = "FileSystemError: File {} cannot be found.", _0
    )]
    FileNotFound(String),
    #[error(
        display = "FileSystemError: Principal or program {:?} cannot be found.",_0
    )]
    IndexNotFound(VeracruzCapabilityIndex),
}

pub(crate) struct FileSystemStub {
    fs: HashMap<String, Vec<u8>>,
}

impl FileSystemStub {
    /// Initialize a new empty buffer.
    pub(crate) fn new() -> Self {
        ChihuahuaBuffer {
            fs: HashMap::new(),
        }
    }

    ///// Buffer a program. Raise an error if there is already a program.
    //pub(crate) fn buffer_program(&mut self, prog: &[u8]) -> Result<(), ChihuahuaBufferError> {
        //if self.program.is_some() {
            //Err(ChihuahuaBufferError::AlreadyHaveBufferedProgram)
        //} else {
            //self.program = Some(prog.to_vec());
            //Ok(())
        //}
    //}

    pub(crate) fn write(&mut self, file_name : &str, buf : &[u8]) -> Result<(),FileSystemError> {
        match self.fs.get_mut(file_name) {
            Some(b) => b.append(buf.clone()),
            None => self.insert(file_name,buf),
        }
        Ok(())
    }

    pub(crate) fn read(&self, file_name : &str) -> Result<Vec<u8>,FileSystemError> {
        Ok(self.fs.get(file_name).map(|v|v.clone()).unwrap_or_else(Vec::new()))
    }

    ///// Buffer a (static) data package. Raise an error if it is a duplicated data package.
    //pub(crate) fn buffer_data(
        //&mut self,
        //package: &DataPackage,
    //) -> Result<(), ChihuahuaBufferError> {
        //let client_id = package.get_client_id();
        //let package_id = package.get_package_id();
        //if Self::buffer_package(&mut self.data, package) {
            //Ok(())
        //} else {
            //Err(ChihuahuaBufferError::AlreadyHaveBufferedData {
                //client_id,
                //package_id,
            //})
        //}
    //}

    ///// Buffer a stream data package. Raise an error if it is a duplicated stream package.
    //pub(crate) fn buffer_stream(
        //&mut self,
        //package: &DataPackage,
    //) -> Result<(), ChihuahuaBufferError> {
        //let client_id = package.get_client_id();
        //let package_id = package.get_package_id();
        //if Self::buffer_package(&mut self.stream, package) {
            //Ok(())
        //} else {
            //Err(ChihuahuaBufferError::AlreadyHaveBufferedStream {
                //client_id,
                //package_id,
            //})
        //}
    //}

    ///// Add the data package into `buffer` and return true if it does not exist, otherwise false.
    //fn buffer_package(
        //buffer: &mut HashMap<ClientID, HashMap<PackageID, DataPackage>>,
        //package: &DataPackage,
    //) -> bool {
        //let client_id = package.get_client_id();
        //let package_id = package.get_package_id();
        //if !buffer.contains_key(&client_id) {
            //buffer.insert(client_id, HashMap::new());
        //}
        //buffer
            //.get_mut(&client_id)
            //.map(|l| {
                //if l.contains_key(&package_id) {
                    //// a package exists
                    //false
                //} else {
                    //l.insert(package_id, package.clone());
                    //true
                //}
            //})
            //// default is false in case, that is, `failure` state.
            //.unwrap_or(false)
    //}

    ///// Assume there is buffered program, otherwise return error
    //pub(crate) fn get_program(&self) -> Result<&[u8], ChihuahuaBufferError> {
        //self.program
            //.as_ref()
            //.map(|l| l.as_slice())
            //.ok_or(ChihuahuaBufferError::NoBufferedProgram)
    //}

    ///// Fetch a buffered (static) data of a client and a package ID.
    ///// Return an error if the data does not exist.
    //pub(crate) fn get_data(
        //&self,
        //client_id: ClientID,
        //package_id: PackageID,
    //) -> Result<&DataPackage, ChihuahuaBufferError> {
        //Self::get_package(&self.data, client_id, package_id).ok_or(
            //ChihuahuaBufferError::NoBufferedData {
                //client_id,
                //package_id,
            //},
        //)
    //}

    ///// Fetch all (static) data packages
    //pub(crate) fn all_data(&self) -> Result<Vec<DataPackage>, ChihuahuaBufferError> {
        //Ok(self
            //.data
            //.values()
            //.map(|l| l.values().map(|m| m.clone()).collect::<Vec<DataPackage>>())
            //.collect::<Vec<Vec<DataPackage>>>()
            //.concat())
    //}

    ///// Fetch a buffered stream data of a client and a package ID.
    ///// Return an error if the data does not exist.
    //pub(crate) fn get_stream(
        //&self,
        //client_id: ClientID,
        //package_id: PackageID,
    //) -> Result<&DataPackage, ChihuahuaBufferError> {
        //Self::get_package(&self.data, client_id, package_id).ok_or(
            //ChihuahuaBufferError::NoBufferedStream {
                //client_id,
                //package_id,
            //},
        //)
    //}

    ///// Fetch the buffered package. If the package does not exist, return None.
    //fn get_package(
        //buffer: &HashMap<ClientID, HashMap<PackageID, DataPackage>>,
        //client_id: ClientID,
        //package_id: PackageID,
    //) -> Option<&DataPackage> {
        //buffer.get(&client_id).map(|l| l.get(&package_id)).flatten()
    //}
}
