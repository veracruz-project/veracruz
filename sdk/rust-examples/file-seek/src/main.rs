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

use std::{fs::File, io::prelude::*, io::SeekFrom};
use anyhow;

const INPUT_FILENAME: &'static str = "/input/README.markdown";
const OUTPUT_FILENAME: &'static str = "/output/NEW_README.markdown";

fn main() -> anyhow::Result<()> {
    let mut f = File::open(INPUT_FILENAME)?;

    // get the number of bytes to skip from the command line arguments
    let args: Vec<String> = std::env::args().collect();
    let cursor_start = args.get(0)
        .unwrap()
        .to_owned()
        .parse::<u64>()?;

    // move the cursor <cursor_start> bytes from the start of the file
    f.seek(SeekFrom::Start(cursor_start))?;

    let mut buf = Vec::new();
    // read from byte number 1000 to the end of file
    f.read_to_end(&mut buf)?;

    let content = String::from_utf8_lossy(&buf).to_string();

    std::fs::write(OUTPUT_FILENAME, content)?;

    Ok(())
}
