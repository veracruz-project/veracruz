pushd /work/rust-optee-trustzone-sdk
#source environment
popd
cargo test --target aarch64-unknown-linux-gnu --no-run --features tz
