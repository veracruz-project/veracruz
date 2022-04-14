# Prime Numbers Generator

This program provides an example of executing multiple programs sequentially inside Veracruz `freestanding-execution-engine`, where each program's input depends on the previous' output. This is similar to the Linux pipeline `command1 | command2 | command3`. 

This is a three-step program where each step is program that provides it's output to the next program. The final output is the primes numbers between 2 and 120. This is a very naive implementation of the [Sieve of Eratosthenes](https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes) algorithms. 

- `generate-set`: this program generates all numbers from 2 to 120
- `remove-two-three-multiples` : this program eliminates any multiple of either 2 or 3 in the generated set
- `remove-five-seven-multiples` : this program eliminates any multiple of either 5 or 7 in the generated set

Here are the steps for running these program inside Veracruz `freestanding-execution-engine`

## Steps 
1. You have to build the WASM binary for each program by running the following commands in each directory:
  ```
  rustup target add wasm32-wasi
  cargo build --target wasm32-wasi
  ```

2. You will find the `.wasm` file in `target/wasm32-wasi/debug/` path inside each program. Copy the three `.wasm` files to `sdk/freestanding-execution-engine`.

3. Inside `sdk/freestanding-execution-engine`, create a directory called `output` and another directory called `program`. 
4. Move the three `.wasm` files inside the `program` directory.

5. Run the following command
```
RUST_LOG="info" cargo run -- --input-source program --program program/generate-set.wasm program/remove-two-three-multiples.wasm program/remove-five-seven-multiples.wasm --output-source output -e -d -c
```
6. After the long log of information, you should see a file called `number-set.txt` inside the output directory. This file should cantain all prime numbers from 2 to 120.
