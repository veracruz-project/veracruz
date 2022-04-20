### (Environment setup)
To get started, we need to install the followings (TinyGo, Golang, Wasmtime): 

### Golang:
Go to https://go.dev/ (try to install between 1.15 to 1.17 , cause TinyGo supports Golang language of these versions only), after that follow the instructions given there

### TinyGo:
Its a Golang compiler and to install this go to https://tinygo.org/getting-started/install/ and follow the instructions given there

### Wasmtime:
Go to https://wasmtime.dev/

### There are two things to do here, 
(1) compile source code in high level languages, for examples Golang to Wasm, 
(2) execute the Wasm via some engines, for examples: Wasmtime.

### Part 1 (compile source code in high level languages)

(1) For that first step lets build simple Golang program that creates fibonacci sequence of an integer input.

(2) Create a folder "Golang-to-WASI" :
   mkdir Golang-to-WASI
   cd Golang-to-WASI

(3) Create a file named *.go :  // replace * with program name, example: fibonacci.go 
   touch *.go

(4) Add the program there 

(5) Compile to Wasm using the following lines:
   tinygo build -wasm-abi=generic -target=wasi -o *.wasm *.go

(6) The Wasmfile created in the folder:
   file *.wasm

### Part 2 (execute the Wasm via some engines)

(1) Executing using Wasmtime :
   wasmtime *.wasm


