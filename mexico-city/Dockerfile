# Note to self: Alpine Linux is the devil and should not be used
FROM alpine:latest
# copy the vsock-sample binary
COPY target/x86_64-unknown-linux-musl/release/mexico_city_enclave .
# start the server inside the enclave
CMD export RUST_BACKTRACE=1 && cat ./mexico_city_enclave >> /dev/random && cat ./mexico_city_enclave >> /dev/random && cat ./mexico_city_enclave >> /dev/random && cat ./mexico_city_enclave >> /dev/random && ./mexico_city_enclave
