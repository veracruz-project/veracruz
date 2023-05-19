# Note to self: Alpine Linux is the devil and should not be used
FROM alpine:latest
# copy the vsock-sample binary
COPY runtime-manager-enclave .
# start the server inside the enclave
CMD export RUST_BACKTRACE=1 && ./runtime-manager-enclave
