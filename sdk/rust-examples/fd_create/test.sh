#!/bin/sh

# This test script is not ready to be released!

set -e

cargo build --target=wasm32-wasi

( cd ../../freestanding-execution-engine/ && cargo build )

RUN=../../freestanding-execution-engine/target/debug/freestanding-execution-engine
RUNARGS="--program target/wasm32-wasi/debug/fd_create.wasm --input-source target/wasm32-wasi/debug"

"$RUN" $RUNARGS -d -e -x jit
"$RUN" $RUNARGS -d -e -x interp
