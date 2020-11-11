# Note to self: Alpine Linux is the devil and should not be used
FROM alpine:latest
# copy the vsock-sample binary
COPY target/x86_64-unknown-linux-musl/release/chiapas .
# start the server inside the enclave
CMD export RUST_BACKTRACE=1 && cat ./chiapas >> /dev/random && cat ./chiapas >> /dev/random && cat ./chiapas >> /dev/random && cat ./chiapas >> /dev/random && ./chiapas
