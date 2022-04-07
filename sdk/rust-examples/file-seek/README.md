# A Simple file seeker with Veracruz freestanding execution engine


This is a simple program that lets you move the cursor inside a text file for a number of bytes that specify, read the remaining file after the cursor and write the output into anothe text file.
We provided a text file, `rust-std.txt`, which is the introduction of the Rust Standard Library Documentation.

# Steps

1. Go to `sdk/freestanding-execution-engine` directory

2. run `cp -r ../rust-examples/file-seek .`. This will copy the current directory to the Veracruz freestanding execution engine. 

3. Inside `sdk/freestanding-execution-engine`, Create a directory called `input`, and another directory called `output`.

4. Run the following command `cp ../../README.markdown input`, this will copy the Veracruz README file to the input directory to be our input to the program.

5. Go to `file-seek` directory and run the following commands
  ```
  rustup target add wasm32-wasi
  cargo build --target wasm32-wasi
  ```
The first command adds WebAssembly (WASM) as the compilation target, so the rust program can be compiled to WASM. The second command complies the code into WASM

6. Inside `file-seek` directory, Run `cp target/wasm32-wasi/debug/file-seek.wasm .`. 
  This will copy the WASM file to the root of the project to be accessed easily.

7. Go back to `freestanding-execution-engine` directory and Run the following command
```
RUST_LOG="info" cargo run -- --arg 1000 --input-source input --input-source file-seek --program file-seek/file-seek.wasm --output-source output -e -d -c
```
The number after `--arg` is the number of bytes that you want to skip from the begining of the text file. Feel free to change it to whatever you want.

8. You should have seen a very long log of information. Go to the `output` directory and you should see the `NEW_README.markdown` file and it should the remainder of the text file after skipping the desired number of bytes.
