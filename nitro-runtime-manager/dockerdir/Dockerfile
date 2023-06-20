# Note to self: Alpine Linux is the devil and should not be used
FROM alpine:latest
# copy the vsock-sample binary
COPY nitro_runtime_manager .
# start the server inside the enclave
CMD export RUST_BACKTRACE=1 && ./nitro_runtime_manager
