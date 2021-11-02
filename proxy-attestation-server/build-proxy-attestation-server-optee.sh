#pushd /work/rust-optee-trustzone-sdk
#source environment
#popd
cargo build -j 1 --features tz --target aarch64-unknown-linux-gnu
