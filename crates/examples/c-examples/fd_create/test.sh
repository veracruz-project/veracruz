#!/bin/sh

# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.md` file in the Veracruz root directory
# for licensing and copyright information.

set -e

export WASI_BASE=/work/veracruz/wasi-sdk

export WASI_VERSION=12
export WASI_VERSION_FULL=${WASI_VERSION}.0
export WASI_SDK_PATH=$WASI_BASE/wasi-sdk-${WASI_VERSION_FULL}
export WASM_CC="${WASI_SDK_PATH}/bin/clang "\
"--sysroot=${WASI_SDK_PATH}/share/wasi-sysroot"

if ! [ -d "$WASI_BASE" ] ; then
    if [ "$install_wasi_sdk" != yes ] ; then
        echo Run with install_wasi_sdk=yes to install WASI SDK.
        exit 1
    else
        mkdir -p "$WASI_BASE"
        (
            cd "$WASI_BASE"
            wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/wasi-sdk-${WASI_VERSION_FULL}-linux.tar.gz
            tar xvf wasi-sdk-${WASI_VERSION_FULL}-linux.tar.gz
        )
        echo WASI SDK installed.
        exit 0
    fi
fi

$WASM_CC -Wall -O2 prog.c -o prog.wasm

( cd ../../../sdk/freestanding-execution-engine/ && cargo build )

RUN=../../../sdk/freestanding-execution-engine/target/debug/freestanding-execution-engine

"$RUN" --pipeline prog.wasm --input-source . -d -e -x jit
"$RUN" --pipeline prog.wasm --input-source . -d -e -x interp
