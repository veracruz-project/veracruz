use pinecone::to_vec;
use std::fs;
use std::str;
fn main() -> anyhow::Result<()>  {
    println!("Hello, world!");
    fs::write("/services/pinecone_string.dat", to_vec("hello rust")?)?;
    let rst = fs::read("/services/pinecone_result.dat")?;
    let rst = fs::read("/services/pinecone_result.dat")?;
    println!("{}",str::from_utf8(&rst)?);
    Ok(())
}
