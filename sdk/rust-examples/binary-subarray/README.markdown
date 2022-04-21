# Binary Subarrays

This program provides an example of executing multiple programs sequentially inside Veracruz `freestanding-execution-engine`, where each program's input depends on the previous' output.   This is similar to piping commands in Linux `command1 | command2`.  
  
This is a two-step program where the first step provides its output to the second program. The final output consists of three subarrays: 1. The longest alternating subarray(010101..), 2. The longest subarray containing only 0s, and 3. The longest subarray containing only 1s.   
  
1. `ascii-to-bin`: this program converts ASCII characters to binary 0s and 1s using the Huffman Encoding algorithm.  
2. `longest-subarrays`: this takes the output provided by the previous program, and outputs the three subarrays mentioned above.

Here are the steps for running these two programs inside Veracruz `freestanding-execution-engine`

## Steps  

1. You have to build the WASM binary for each program by running the following commands in each directory:
  ```
  rustup target add wasm32-wasi
  cargo build --target wasm32-wasi
  ```

2. You will find the `.wasm` file in `target/wasm32-wasi/debug/` path inside each program. Copy the two `.wasm` files to `sdk/freestanding-execution-engine`.

3. Inside `sdk/freestanding-execution-engine`, create three directories, called `input`, `output` and another directory called `program`. 

4. Run the following command :
```
cp ../../test-collateral/huffman_example_input.txt input
```
This will copy the "Veracruz README file" to the input directory. This will be our input to the program 1, `ascii-to-bin`.

5. Move the two `.wasm` files inside the `program` directory.

6. Run the following command
```
RUST_LOG="info" cargo run -- --input-source input --input-source program --program program/ascii-to-bin.wasm program/longest-subarrays.wasm --output-source output -e -d -c
```

7. After the long log of information, you should see a file called `output.txt` inside the output directory. This file should contain `the three subarrays` mentioned above, in the same order as mentioned above.