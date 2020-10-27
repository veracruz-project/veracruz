pushd /work/rust-optee-trustzone-sdk
source environment
unset CC
popd
cargo test --features tz --target aarch64-unknown-linux-gnu --no-run
