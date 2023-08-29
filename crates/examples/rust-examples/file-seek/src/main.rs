//! File Seeker Example
//!
//! ## Context
//!
//! Read a file, move the cursor forward for a number of bytes and write the remaining bytes into
//! another text file
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use anyhow;
use std::{fs::File, io::prelude::*, io::SeekFrom};

const INPUT_FILENAME: &'static str = "/input/README.markdown";
const OUTPUT_FILENAME: &'static str = "/output/NEW_README.markdown";

fn main() -> anyhow::Result<()> {
    let mut f = File::open(INPUT_FILENAME)?;

    // get the number of bytes to skip from the environment
    let cursor_start = std::env::var("SKIP")?.parse::<u64>()?;

    // move the cursor <cursor_start> bytes from the start of the file
    f.seek(SeekFrom::Start(cursor_start))?;

    let mut buf = Vec::new();
    // read from byte number 1000 to the end of file
    f.read_to_end(&mut buf)?;

    let content = String::from_utf8_lossy(&buf).to_string();

    std::fs::write(OUTPUT_FILENAME, content)?;

    Ok(())
}
