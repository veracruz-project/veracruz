#!/bin/sh

# This test script is not ready to be released!

set -e

#xx Hardwired reference to toolchain, already installed:
export WASI_BASE=/data/wasi-sdk

export WASI_VERSION=12
export WASI_VERSION_FULL=${WASI_VERSION}.0
export WASI_SDK_PATH=$WASI_BASE/wasi-sdk-${WASI_VERSION_FULL}
export WASM_CC="${WASI_SDK_PATH}/bin/clang "\
"--sysroot=${WASI_SDK_PATH}/share/wasi-sysroot"

$WASM_CC -Wall -O2 prog.c -o prog.wasm

( cd ../freestanding-execution-engine/ && cargo build )

RUN=../freestanding-execution-engine/target/debug/freestanding-execution-engine

"$RUN" --program prog.wasm --input-source . -d -e -x jit
"$RUN" --program prog.wasm --input-source . -d -e -x interp
