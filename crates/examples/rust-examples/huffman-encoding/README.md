# A simple Huffman Encoding implementation with Veracruz freestanding execution engine

This simple program lets you implement the "Huffman Encoding Algorithm, " a Lossless Compression Algorithm used to compress Data. It was developed by David A. Huffman.
This directory is a simple program that takes a file called `huffman_example_input.txt` and compresses its data using the Huffman Encoding Algorithm, and then writes the output into `encoded_output.txt`

# Steps

1. Go to the `sdk/freestanding-execution-engine` directory.

2. run `cp -r ../../examples/rust-examples/huffman-encoding .`. This will copy the current directory to the Veracruz freestanding execution engine.

3. Inside the `sdk/freestanding-execution-engine`, Create a directory called `input`, and another directory called `output`.

4. Run the command `cp ../../README.md input/hello-world-1.dat`. This will copy the Veracruz README file to the input directory to be our input to the program.

5. Go to the `huffman-encoding` directory and run the following commands:
```
rustup target add wasm32-wasi
cargo build --target wasm32-wasi
```

The first command adds WebAssembly (WASM) as the compilation target, so the rust program can be compiled to WASM.
The second command compiles the code into WASM.

6. Inside the `huffman-encoding` directory, Run:
```
cp target/wasm32-wasi/debug/huffman-encoding.wasm .
```
This will copy the WASM file to the project's root to be accessed easily.

7. Go back to `freestanding-execution-engine` directory and Run the following command:
```
RUST_LOG="info" cargo run -- --input-source input --input-source huffman-encoding --pipeline huffman-encoding/huffman-encoding.wasm --output-source output -e -d -c
```

8. Go to the `output` directory and you should see `encoded_output.txt` file, and it will contain two representations of the input text. The first is the encoded version, and the second is the original version again, which has been decoded from the encoded version. Thus showing that this is a "lossless" compression algorithm.
