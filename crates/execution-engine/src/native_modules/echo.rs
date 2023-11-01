use crate::native_modules::common::StaticNativeModule;
use anyhow::Result;
use std::{path::Path, fs::{read, write}};

pub(crate) struct EchoService;

impl StaticNativeModule for EchoService {
    fn name(&self) -> &str {
        "Echo Service"
    }

    fn serve(&mut self, input: &Path, output: &Path) -> Result<()> {
        let buf = read(input)?;
        write(output, buf)?;
        Ok(())
    }
}

impl EchoService {
    pub(crate) fn new() -> Self {
        Self {}
    }
}
