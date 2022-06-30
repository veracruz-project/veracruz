# A simple string-search program, implemented using Veracruz freestanding execution engine (case sensitive, only for ASCII)


This simple version of search lets you input query text as argument, and an input file. Then, it will print all the lines in the input file, where the query text occurs. It'll then output this result into `search_results.txt`

# Steps

1. Go to `sdk/freestanding-execution-engine` directory

2. run `cp -r ../rust-examples/string-search .`. This will copy the current directory to the Veracruz freestanding execution engine. 

3. Inside `sdk/freestanding-execution-engine`, Create a directory called `input`, and another directory called `output`.

4. Run the following command `cp -r ../../test-collateral/random_search_text input`, this will copy the Veracruz README file to the input directory to be our input to the program.

5. Go to `string-search` directory and run the following commands
  ```
  rustup target add wasm32-wasi
  cargo build --target wasm32-wasi
  ```
The first command adds WebAssembly (WASM) as the compilation target, so the rust program can be compiled to WASM. The second command compiles the code into WASM

6. Inside `string-search` directory, Run `cp target/wasm32-wasi/debug/string-search.wasm .`. 
  This will copy the WASM file to the root of the project to be accessed easily.

7. Go back to `freestanding-execution-engine` directory and Run the following command
```
RUST_LOG="info" cargo run -- --arg "in" --input-source input --input-source string-search --program string-search/string-search.wasm --output-source output -e -d -c
```
The string after `--arg` is the `search query` that you want to search for in the text file. Feel free to change it to whatever you want. Here, `in` is just an example of a common word, which is more likely to occur in different texts.  
Use `"query text"` double quotes, when using multiple words for searching, to keep the formatting of whitespaces in the search query intact.

8. You should have seen a very long log of information. Go to the `output` directory, and you should see the `search_results.txt` file, and it will contain all the lines where that word was seen.
