use std::fs;
use std::time::Instant;
use std::str;
fn main() -> anyhow::Result<()>  {
    let input = fs::read("/input/pinecone_string.dat")?;
    let now = Instant::now();
    fs::write("/services/pinecone_string.dat", input)?;
    let rst = fs::read("/services/pinecone_result.dat")?;
    println!("time: {} ms", now.elapsed().as_micros());
    Ok(())
}
