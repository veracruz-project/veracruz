# A Simple I/O program with Veracruz freestanding execution engine

This is a walkthrough of how to load a file from the host to the Veracruz freestanding execution engine, perform some simple operations, and write the output file to the host.

This directory is a simple program that takes a file called `unsorted_numbers.txt`, which contains numbers from 1 to 9 in random order, sorts the numbers, and writes the output into `sorted_numbers.txt`.

# Steps

1. Go to the directory `sdk/freestanding-execution-engine`.

2. Run `cp -r ../../examples/rust-examples/sort-numbers .`. This will copy this directory to the Veracruz freestanding execution engine.

3. Inside `sdk/freestanding-execution-engine`, create a directory called `output`, which will be used for input and output.

4. Run the following command :
```
echo 7,4,8,5,6,9,3,1,2 > output/unsorted_numbers.txt
```
This will be our input to the program.

5. Go to the `sort-numbers` directory and run the following commands
```
rustup target add wasm32-wasi
cargo build --target wasm32-wasi
```
The first command adds WebAssembly (WASM) as the compilation target, so the rust program can be compiled to WASM. The second command complies the code into WASM.

6. Inside `sort-numbers` directory, run `cp target/wasm32-wasi/debug/sort-numbers.wasm .`.
This will copy the WASM file to the root of the project to be accessed easily.

7. Go back to `freestanding-execution-engine` directory and run the following command:
```
RUST_LOG="info" cargo run -- --input-source output --input-source sort-numbers --pipeline sort-numbers/sort-numbers.wasm --output-source output -e -d -c
```

8. You should have seen a very long log of information. Go to the `output` directory and you should see the `sorted_numbers.txt` file and it should contain all the numbers from 0 to 999 sorted.
