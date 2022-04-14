# Prime Numbers Generator

This program provides an example of executing multiple programs sequentially inside Veracruz `freestanding-execution-engine`, where each program's input depends on the previous' output. This is similar to the Linux pipeline `command1 | command2 | command3`. 

This is a two-step program where the first step proveds its output to the second program. The final output is the primes numbers between 2 and `upper_limit`, which you will specify . This is an implementation of the [Sieve of Eratosthenes](https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes) algorithms. 

- `generate-set`: this program generates all numbers from 2 to `upper_limit` 
- `keep-primes`: this takes the set provided by the previous program, applies Sieve of Eratosthenes algorithms, and keeps only primes numbers

Here are the steps for running these program inside Veracruz `freestanding-execution-engine`

## Steps 
1. You have to build the WASM binary for each program by running the following commands in each directory:
  ```
  rustup target add wasm32-wasi
  cargo build --target wasm32-wasi
  ```

2. You will find the `.wasm` file in `target/wasm32-wasi/debug/` path inside each program. Copy the three `.wasm` files to `sdk/freestanding-execution-engine`.

3. Inside `sdk/freestanding-execution-engine`, create a directory called `output` and another directory called `program`. 
4. Move the two `.wasm` files inside the `program` directory.

5. Run the following command
```
RUST_LOG="info" cargo run -- --arg 1000 --input-source program --program program/generate-set.wasm program/keep-primes.wasm --output-source output -e -d -c
```
you can change the number after `--arg` to change the `upper_limit` value.

6. After the long log of information, you should see a file called `number-set.txt` inside the output directory. This file should cantain all prime numbers between 2 and `upper_limit` .
