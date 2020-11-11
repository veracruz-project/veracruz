all: chiapas.eif

target/x86_64-unknown-linux-musl/release/chiapas: Cargo.toml src/*.rs
	cargo build --target x86_64-unknown-linux-musl --release

chiapas.eif: target/x86_64-unknown-linux-musl/release/chiapas Dockerfile
	nitro-cli build-enclave --docker-dir . --docker-uri chiapas --output-file chiapas.eif
