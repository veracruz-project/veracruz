#!/bin/sh

# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory
# for licensing and copyright information.

set -e

cargo build --target=wasm32-wasi

( cd ../../../sdk/freestanding-execution-engine/ && cargo build )

RUN=../../../sdk/freestanding-execution-engine/target/debug/freestanding-execution-engine
RUNARGS="--pipeline target/wasm32-wasi/debug/fd-create.wasm --input-source target/wasm32-wasi/debug"

"$RUN" $RUNARGS -d -e -x jit
"$RUN" $RUNARGS -d -e -x interp
