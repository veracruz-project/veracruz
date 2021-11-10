use pinecone::from_bytes;
use crate::fs::{Service, FileSystemResult};
use wasi_types::ErrNo;

pub(crate) struct PineconeService;

impl Service for PineconeService {
    fn name(&self) -> &str {
        "Pinecone Service"
    }

    fn serve(&self, inputs: &[Vec<u8>]) -> FileSystemResult<Vec<u8>> {
        if inputs.len() != 1 {
            return Err(ErrNo::Inval);
        }
        Ok(from_bytes::<String>(&inputs[0]).map_err(|_| ErrNo::Inval)?.as_bytes().to_vec())
    }
}

impl PineconeService {
    pub(crate) fn new() -> Self {
        Self{}
    }
}
