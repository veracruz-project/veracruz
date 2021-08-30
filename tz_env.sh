cd /work/rust-optee-trustzone-sdk/ && source environment
unset CC
export CC_aarch64_unknown_optee_trustzone=/work/rust-optee-trustzone-sdk/optee/toolchains/aarch64/bin/aarch64-linux-gnu-gcc
export CC_x86_64_unknown_linux_gnu=gcc
source $CARGO_HOME/env
