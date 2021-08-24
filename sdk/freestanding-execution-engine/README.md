# Getting started with the Veracruz freestanding execution engine

This document provides a walkthrough of how to load files from the host and into the Veracruz freestanding execution engine. The freestanding execution engine allows programs to be executed and is used for debugging and development outside of a real Veracruz instance.

IMPORTANT: This exercise assume some familiarity with reading **Rust syntax** and **Rust's package manager named Cargo**. Both these areas are well explained at this [link](https://doc.rust-lang.org/book/title-page.html).

# Steps:
1. Install [Rust](https://www.rust-lang.org/tools/install).
2. Clone the Veracruz repository from [Github](https://github.com/veracruz-project/veracruz)
3. Open up a terminal and go to the directory `veracruz/sdk/rust-examples`. In this example we will be focusing on the `read-file` directory
4. Run the following commands
  ```
  rustup target add wasm32-wasi
  cargo build --target wasm32-wasi
  ```
The first command adds WebAssembly (WASM) as the compilation target, so the rust program can be compiled to WASM. The second command complies the code that is inside src, which is usually a file named `main.rs`, into WASM. Once the second command has been run you should expect to see a WASM file inside the directory `read-file/target/wasm32-wasi/debug/read-file.wasm`.
  
5. Copy `read-file.wasm` into the directory `veracruz/sdk/freestanding-execution-environment`
6. If you read what was inside main.rs in `read-file/src` you will have noticed that the program has an input file called `input.txt` and two outputs; a file called `output` and a directory called `a/b/c/d/e.txt`. We need to create `input.txt` to feed into the program; so create `input.txt` inside the freestanding-execution-engine directory and write in anything to the contents of the file. We also need to create the directory `a/b/c/d` inside the freestanding-execution-engine directory.
7. Now you are setup to run the main command that executes the WASM program inside the Veracruz engine! Below is the command, it is a long one, but we will break down.
```
RUST_LOG="info" cargo run -- --program read-file.wasm --input-source input.txt --output-source a --output-source output -d -e
```

- `RUST_LOG` is an environment variable that in this case we set to `info` to print out information about the execution of the WASM program
- `freestanding-execution-engine` itself is a cargo project, therefore we use cargo run to start the build and execution of it
- The `--program` tag allows to specify which .wasm program we want to execute
- The `--input-source` tag allows us to specify the input of the WASM program we are using, in this case it is the `input.txt` file we created previously
- The `--output-source` tags allow us to specify where the output of the program will be put. In this case there are two output sources. The first output source is a directory written as `a` which is a short hand for `a/b/c/d/e.txt` to allow for permissions to be checked at top level directory (you will be able to see this full directory in `main.rs` inside the read-file). The second output is simply a file named `output` which will have a complex string written to it. This is because as part of the program read-file.wasm this string is built using Rust functions and is written to the `output` file.
- The `-d` and `-e` tags respectively dump stdout and stderr

8. Once this command has been run you should have a very long log of information outputted onto the terminal. Some of the output will be familiar in terms of the file/directory names and the strings that have been written to the output files. However most of the output will not make much sense. Take a look at the `INFO` lines; they log the actions being done as part of the execution. You may also be able to see `stdout dump` (standard out) which displays output to the terminal and `stderr` (standard error) which displays any errors that occurred during the execution
9. Explore around the output files and try to make connections between the program written in `main.rs` (in `read-file`) and what has appeared in the output files and `stdout`. You will see that output will have the complex string written to it. `a/b/c/d/e.txt` will have "hello" written to it; it will have replaced the previous contents of it. `stdout` also displays "hello".
10. Try changing the contents of the `main.rs` file inside read-file and use the steps above to compile it to WASM and see the output in the output files as well as `stdout`. This is a good exercise to solidify your understanding in how the engine works.
11. Extension exercise: read-file is just one of the example programs inside `rust-examples` that we can run in the engine. Try using other examples in the `rust-examples` folder to test out the engine
