use std::{fs, process::exit};
use wasi_types::ErrNo;

fn compute() -> Result<(), ErrNo> {
    let input = "/input.txt";
    let output = "/output";

    let f = fs::read(input)?;
    let rst = pinecone::to_vec(&f).map_err(|_| ErrNo::Proto)?;
    fs::write(output, rst)?;
    Ok(())
}

fn main() {
    if let Err(e) = compute() {
        exit((e as u16).into());
    }
}
