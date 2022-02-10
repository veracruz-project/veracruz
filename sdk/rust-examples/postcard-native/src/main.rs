use std::fs;
use std::time::Instant;
fn main() -> anyhow::Result<()>  {
    let input = fs::read("/input/postcard.dat")?;
    let now = Instant::now();
    fs::write("/services/postcard_string.dat", input)?;
    let rst = fs::read("/services/postcard_result.dat")?;
    fs::write("/output/postcard_native.txt", &rst)?;
    println!("time: {} ms", now.elapsed().as_micros());
    Ok(())
}
