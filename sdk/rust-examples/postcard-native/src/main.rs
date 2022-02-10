use std::fs;
fn main() -> anyhow::Result<()> {
    let input = fs::read("/input/postcard.dat")?;
    fs::write("/services/postcard_string.dat", input)?;
    let rst = fs::read("/services/postcard_result.dat")?;
    fs::write("/output/postcard_native.txt", &rst)?;
    Ok(())
}
