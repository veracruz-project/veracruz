use std::fs;

fn main() {
    let input = "/input.txt";
    let output = "/output";

    let f = fs::read(input).unwrap();
        
    let rst = match pinecone::to_vec(&f) {
        Err(_err) => panic!(),
        Ok(s) => s,
    };
    fs::write(output, rst).unwrap();
}
