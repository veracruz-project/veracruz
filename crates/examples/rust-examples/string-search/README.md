# A simple string-search program, implemented using Veracruz freestanding execution engine (case-sensitive, only for ASCII)

This simple version of search lets you input query text as argument, and an input file. Then it will print all the lines in the input file in which the query text occurs. It will then output this result into `search_results.txt`.

# Steps

1. Go to `sdk/freestanding-execution-engine` directory

2. run `cp -r ../../examples/rust-examples/string-search .`. This will copy the current directory to the Veracruz freestanding execution engine.

3. Inside `sdk/freestanding-execution-engine`, create a directory called `input`, and another directory called `output`.

4. Run the following command `cp -r ../../README.md input/hello-world-1.dat`.
This will copy the Veracruz README file to the input directory to be our input to the program.

5. Go to the `string-search` directory and run the following commands:
```
rustup target add wasm32-wasi
cargo build --target wasm32-wasi
```
The first command adds WebAssembly (WASM) as the compilation target, so the rust program can be compiled to WASM. The second command compiles the code into WASM.

6. Inside the `string-search` directory, run `cp target/wasm32-wasi/debug/string-search.wasm .`.
This will copy the WASM file to the root of the project to be accessed easily.

7. Go back to the `freestanding-execution-engine` directory and run the following command:
```
RUST_LOG="info" cargo run -- --env QUERY="in" --input-source input --input-source string-search --pipeline string-search/string-search.wasm --output-source output -e -d -c
```
The string after `--env QUERY=` is the string that you want to search for in the text file. Feel free to change it to whatever you want. Here `in` is just an example of a common word, which is more likely to occur in different texts.

8. You should have seen a very long log of information. Go to the `output` directory, and you should see the `search_results.txt` file containing all the lines in which that word was seen.
