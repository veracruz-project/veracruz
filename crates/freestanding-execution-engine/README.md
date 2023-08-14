# Getting started with the Veracruz freestanding execution engine

This document provides a walkthrough of how to load files from the host and into the Veracruz freestanding execution engine. The freestanding execution engine allows programs to be executed and is used for debugging and development outside of a real Veracruz instance.

IMPORTANT: This exercise assume some familiarity with reading **Rust syntax** and **Rust's package manager named Cargo**. Both these areas are well explained at this [link](https://doc.rust-lang.org/book/title-page.html).

# Steps:
1. Install [Rust](https://www.rust-lang.org/tools/install).
2. Clone the Veracruz repository from [Github](https://github.com/veracruz-project/veracruz)
3. Open up a terminal and go to the directory `veracruz/examples/rust-examples`. In this example we will be focusing on the `read-file` directory
4. Run the following commands:
```
rustup target add wasm32-wasi
cargo build --target wasm32-wasi
```
The first command adds WebAssembly (WASM) as the compilation target, so the rust program can be compiled to WASM. The second command complies the code that is inside src, which is usually a file named `main.rs`, into WASM. Once the second command has been run you should expect to see a WASM file inside the directory `read-file/target/wasm32-wasi/debug/read-file.wasm`.

5. Copy `read-file.wasm` into the directory `veracruz/sdk/freestanding-execution-engine`.
6. If you read what was inside main.rs in `read-file/src` you will have noticed that the program has an input file called `/input/hello-world-1.dat` and two outputs: `/output/hello-world-1.dat` and `/output/test/test.txt`. We need to create directories for the program, the input and the output: `mkdir program input output`. Move the program into the program directory: `mv read-file.wasm program/`. And create the input file: `echo Test > input/hello-world-1.dat`.
7. Now you are setup to run the main command that executes the WASM program inside the Veracruz engine! The command is below. It is a long one, but we will break it down.
```
RUST_LOG="info" cargo run -- --input-source program --pipeline program/read-file.wasm --input-source input --output-source output -d -e
```

- `RUST_LOG` is an environment variable that in this case we set to `info` to print out information about the execution of the WASM program.
- `freestanding-execution-engine` itself is a cargo project, therefore we use cargo run to start the build and execution of it.
- The `--pipeline` option lets us specify which .wasm program we want to execute.
- The `--input-source` option lets us specify directories for input and for the WASM program itself.
- The `--output-source` option lets us specify where the output of the program will be put.
- The `-d` and `-e` options dump stdout and stderr, respectively.

8. Once this command has been run you should have a very long log of information outputted onto the terminal. Some of the output will be familiar in terms of the file/directory names and the strings that have been written to the output files. However most of the output will not make much sense. Take a look at the `INFO` lines; they log the actions being done as part of the execution. You may also be able to see `stdout dump` (standard out) which displays output to the terminal and `stderr` (standard error) which displays any errors that occurred during the execution
9. Explore around the output files and try to make connections between the program written in `main.rs` (in `read-file`) and what has appeared in the output files and `stdout`. You will see that output will have the complex string written to it. `stdout` also displays "hello".
10. Try changing the contents of the `main.rs` file inside read-file and use the steps above to compile it to WASM and see the output in the output files as well as `stdout`. This is a good exercise to solidify your understanding in how the engine works.
11. Extension exercise: read-file is just one of the example programs inside `rust-examples` that we can run in the engine. Try using other examples in the `rust-examples` folder to test out the engine.
