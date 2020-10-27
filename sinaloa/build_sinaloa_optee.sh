pushd /work/rust-optee-trustzone-sdk
source environment
popd
cargo build --target aarch64-unknown-linux-gnu --features tz --release 
