# A Simple I/O program with Veracruz freestanding execution engine


This is a walkthrough of how to load a file from the host to Veracruz freestanding execution engine, make some simple operations and write the output file to the host.

This directory is a simple program that takes a file called `unsorted_numbers.txt`,which contains numbers from 0 to 999 in random orders, sort the numbers and write the output into `sorted_numbers.txt`  


# Steps

1. Go to `sdk/freestanding-execution-engine` directory

2. run `cp -r ../rust-examples/sort-numbers .`. This will copy the current directory to the Veracruz freestanding execution engine. 

3. Inside `sdk/freestanding-execution-engine`, Create a directory called `input`, and another directory called `output`.

4. Run the following command : 
  ```
  cp ../../test-collateral/unsorted_numbers.txt input
  ```
  This will copy `unsorted_numbers.txt` to the input directory, This will be our input to the program.


5. Go to `sort-numbers` directory and run the following commands
  ```
  rustup target add wasm32-wasi
  cargo build --target wasm32-wasi
  ```
The first command adds WebAssembly (WASM) as the compilation target, so the rust program can be compiled to WASM. The second command complies the code into WASM

6. Inside `sort-numbers` directory, Run `cp target/wasm32-wasi/debug/sort-numbers.wasm .`. 
  This will copy the WASM file to the root of the project to be accessed easily.

7. Go back to `freestanding-execution-engine` directory and Run the following command
```
RUST_LOG="info" cargo run -- --input-source input --input-source sort-numbers --program sort-numbers/sort-numbers.wasm --output-source output -e -d -c
```

8. You should have seen a very long log of information. Go to the `output` directory and you should see the `sorted_numbers.txt` file and it should contain all the numbers from 0 to 999 sorted.
