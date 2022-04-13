Currently no C applications are built automatically as we have chosen
not to depend on a C toolchain that targets Wasm. However, it is
possible to install a toolchain and run one test with the freestanding
execution engine as follows:
```
cd sdk/c-examples/fd-create
install_wasi_sdk=yes ./test.sh
```
