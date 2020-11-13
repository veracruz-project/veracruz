# Note to self: Alpine Linux is the devil and should not be used
FROM alpine:latest
# copy the vsock-sample binary
COPY target/x86_64-unknown-linux-musl/release/nitro-root-enclave .
# start the server inside the enclave
CMD export RUST_BACKTRACE=1 && cat ./nitro-root-enclave >> /dev/random && cat ./nitro-root-enclave >> /dev/random && cat ./nitro-root-enclave >> /dev/random && cat ./nitro-root-enclave >> /dev/random && ./nitro-root-enclave
