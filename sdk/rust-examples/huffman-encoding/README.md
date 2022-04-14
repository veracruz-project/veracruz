# A simple huffman encoding implementation with Veracruz freestanding execution engine


This is a simple program that lets you implement the "Huffman Encoding Algorithm" which is a Lossless Compression Algorithm used to compresss Data. It was developed by David A. Huffman.  
This directory is a simple program that takes a file called `huffman_example_input.txt` and compresses its data using the Huffman Encoding Algorithm, and then writes teh output into `encoded_output.txt`

# Steps

1. Go to `sdk/freestanding-execution-engine` directory.

2. run `cp -r ../rust-examples/huffman-encoding .`. This will copy the current directory to the Veracruz freestanding execution engine.

3. Inside `sdk/freestanding-execution-engine`, Create a directory called `input`, and another directory called `output`.

4. Run the following command :
```
cp ../../test-collateral/huffman_example_input.txt input
```
This will copy the "Veracruz README file" to the input directory. This will be our input to the program.

5. Go to `huffman-encoding` directory and run the following commands :
```
rustup target add wasm32-wasi
cargo build --target wasm32-wasi
```

The first command adds WebAssembly (WASM) as the compilation target, so the rust program can be compiled to WASM.  
The second command compiles the code into WASM.

6. Inside `huffman-encoding` directory, Run : 
```
cp target/wasm32-wasi/debug/huffman-encoding.wasm .
```
This will copy the WASM file to the root of the project to be accessed easily.

7. Go back to `freestanding-execution-engine` directory and Run the following command :
```
RUST_LOG="info" cargo run -- --input-source input --input-source huffman-encoding --program huffman-encoding/huffman-encoding.wasm --output-source output -e -d -c
```

8. Go to the `output` directory and you should see `encoded_output.txt` file, and it will contain two representations of the input text. The first is the encoded version, and the second is the original version again, which has been decoded from the encoded version. Thus showing that this is a "lossless" compression algorithm.