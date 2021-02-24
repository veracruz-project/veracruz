///! GLUE CODE FOR NEW API.
///! IT SHOULD BE REPLACED BY VFS IMPLEMENTATION OF WASI API.

use err_derive::Error;
use std::{collections::HashMap, result::Result, vec::Vec, string::{ToString, String}};
use veracruz_utils::{VeracruzCapabilityIndex, VeracruzCapability, VeracruzCapabilityTable};

/// Error type for mexico-city buffer.
#[derive(Clone, Debug, Error)]
pub enum VFSError {
    //TODO: potential remove this 
    #[error(
        display = "VFSError: File {} cannot be found.", _0
    )]
    FileNotFound(String),
    #[error(
        display = "VFSError: Principal or program {:?} cannot be found.",_0
    )]
    IndexNotFound(VeracruzCapabilityIndex),
    #[error(
        display = "VFSError: Client {:?} is disallowed to {:?}.",client_id,operation
    )]
    CapabilityDenial {
        client_id: VeracruzCapabilityIndex,
        operation : VeracruzCapability,
    },
    #[error(
        display = "VFSError: File {:?} digest mismatches, model: {:?}, received: {:?}.",file_name, model, received
    )]
    FileDigestMismatch{
        file_name : String,
        model : Vec<u8>,
        received : Vec<u8>,
    },
}

/// Buffer for storing program, (static) data, and stream data.
#[derive(Clone, Debug)]
pub struct VFS {
    fs: HashMap<String, Vec<u8>>,
    capabilities: VeracruzCapabilityTable,
    digests: HashMap<String, Vec<u8>>,
}

impl VFS {
    /// Computes a SHA-256 digest of the bytes passed to it in `buffer`.
    pub fn sha_256_digest(buffer: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, buffer)
            .as_ref()
            .to_vec()
    }

    /// Initialize a new empty buffer.
    pub fn new(capabilities: &VeracruzCapabilityTable, digests: &HashMap<String, Vec<u8>>) -> Self {
        VFS {
            fs: HashMap::new(),
            capabilities: capabilities.clone(),
            digests: digests.clone(),
        }
    }
    
    pub fn write(&mut self, file_name : &str, new_data : &[u8]) -> Result<(),VFSError> {
        self.fs.remove(file_name);
        assert!(!self.fs.contains_key(file_name));
        self.fs.insert(file_name.to_string(),new_data.to_vec());
        self.digest_check(file_name,new_data)
    }

    pub fn append_write(&mut self, file_name : &str, buf : &[u8]) -> Result<(),VFSError> {
        match self.fs.get_mut(file_name) {
            Some(b) => {
                b.append(&mut buf.to_vec());
            },
            None => {
                self.fs.insert(file_name.to_string(),buf.to_vec());
            },
        };
        self.digest_check(file_name,self.fs.get(file_name).unwrap())
    }

    fn digest_check(&self, file_name: &str, new_data: &[u8]) -> Result<(),VFSError> {
        if let Some(digest) = self.digests.get(file_name) {
            let new_digest = Self::sha_256_digest(new_data);
            if new_digest.len() != digest.len() {
                return Err(VFSError::FileDigestMismatch{file_name : file_name.to_string(), model: digest.to_vec(), received: new_digest.to_vec()});
            }
            for (lhs, rhs) in digest.iter().zip(new_digest.iter()) {
                if lhs != rhs {
                    return Err(VFSError::FileDigestMismatch{file_name : file_name.to_string(), model: digest.to_vec(), received: new_digest.to_vec()});
                }
            }
        }
        Ok(())
    }

    pub fn read(&self, file_name : &str) -> Result<Option<Vec<u8>>,VFSError> {
        Ok(self.fs.get(file_name).map(|v|v.clone()))
    }

    // NOTE: the following function should match wasi api.
    /// Return Some(CapabilityFlags) if `id` has the permission 
    /// to read, write and execute on the `file_name`.
    /// Return None if `id` or `file_name` do not exist.
    pub fn check_capability(&self, id: &VeracruzCapabilityIndex, file_name: &str, cap: &VeracruzCapability) -> Result<(), VFSError> {
        self.capabilities
            .get(id)
            .ok_or(VFSError::IndexNotFound(id.clone()))?
            .get(file_name)
            .ok_or(VFSError::FileNotFound(file_name.to_string()))
            .and_then(|p| {
                if p.contains(cap) {
                    Ok(())
                } else {
                    Err(VFSError::CapabilityDenial{
                        client_id: id.clone(),
                        operation: cap.clone(),
                    })
                }
            })
    }
}
