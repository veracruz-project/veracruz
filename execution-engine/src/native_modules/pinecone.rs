use pinecone::from_bytes;
use crate::fs::{Service, FileSystem, FileSystemResult};
use wasi_types::ErrNo;

pub(crate) struct PineconeService;

impl Service for PineconeService {
    fn name(&self) -> &str {
        "Pinecone Service"
    }

    fn serve(&self, fs: &mut FileSystem, inputs: &[u8]) -> FileSystemResult<()> {
        let v = from_bytes::<String>(inputs).map_err(|_| ErrNo::Inval)?.as_bytes().to_vec();
        fs.write_file_by_absolute_path("/services/pinecone_result.dat", v, false)?;
        Ok(())
    }

    fn try_parse(&self, _input: &[u8]) -> FileSystemResult<bool> {
        Ok(true)
    }
}

impl PineconeService {
    pub(crate) fn new() -> Self {
        Self{}
    }
}
