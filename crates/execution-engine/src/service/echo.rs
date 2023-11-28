use crate::Execution;
use anyhow::Result;
use std::{path::Path, fs::{read, write}};

pub(crate) struct EchoService;

impl Execution for EchoService {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn execute(&mut self, dir: &Path) -> Result<()> {
        let input = dir.join("input");
        let output = dir.join("output");
        let buf = read(input)?;
        write(output, buf)?;
        Ok(())
    }
}

impl EchoService {
    pub(crate) const NAME: &'static str = "Echo Service";
    pub(crate) fn new() -> Self {
        Self {}
    }
}
