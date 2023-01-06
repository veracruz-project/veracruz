//! Generate a large output file.

use std::fs::File;
use std::io::Write;

fn main() -> anyhow::Result<()> {
    let mut f = File::create("/output/file.dat")?;
    let len = 1;
    let buf = vec![0; len];
    f.write_all(&buf)?;
    Ok(())
}
