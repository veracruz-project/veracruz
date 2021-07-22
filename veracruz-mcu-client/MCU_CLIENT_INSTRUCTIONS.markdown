
# MCU client demo

This is a quick guide on how to run the MCU client demo. It assumes you have
already set up a Veracru build environment (see [BUILD_INSTRUCTIONS.markdown](../BUILD_INSTRUCTIONS.markdown)),
and are familiar with running the Veracruz server.


## Setup and servers

First we need to setup the Veracruz computation and server instances.

Build the demo computation:

``` bash server
$ mkdir -p veracruz-mcu-client/example
$ make -C sdk/rust-examples/audio-event-triangulation
$ cp sdk/rust-examples/audio-event-triangulation/target/wasm32-wasi/release/audio-event-triangulation.wasm veracruz-mcu-client/example/audio-event-triangulation.wasm
```

Setup identities:

``` bash server
$ openssl genrsa -out veracruz-mcu-client/example/controller-key.pem 2048
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key veracruz-mcu-client/example/controller-key.pem \
    -out veracruz-mcu-client/example/controller-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa -out veracruz-mcu-client/example/mcu0-key.pem 2048
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key veracruz-mcu-client/example/mcu0-key.pem \
    -out veracruz-mcu-client/example/mcu0-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa -out veracruz-mcu-client/example/mcu1-key.pem 2048
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key veracruz-mcu-client/example/mcu1-key.pem \
    -out veracruz-mcu-client/example/mcu1-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa -out veracruz-mcu-client/example/mcu2-key.pem 2048
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key veracruz-mcu-client/example/mcu2-key.pem \
    -out veracruz-mcu-client/example/mcu2-cert.pem \
    -config test-collateral/cert.conf

$ openssl ecparam -name prime256v1 -genkey -noout \
    -out veracruz-mcu-client/example/ca-key.pem
$ openssl req -new -x509 -sha256 -nodes -days 1825 \
    -subj "/C=Mx/ST=Veracruz/L=Veracruz/O=Veracruz/OU=Proxy/CN=VeracruzProxyServer" \
    -key veracruz-mcu-client/example/ca-key.pem \
    -out veracruz-mcu-client/example/ca-cert.pem \
    -config test-collateral/ca-cert.conf
```

Generate the policy:

``` bash server
$ vc-pgen \
    --proxy-attestation-server-ip 172.17.0.2:3010 \
    --proxy-attestation-server-cert veracruz-mcu-client/example/ca-cert.pem \
    --veracruz-server-ip 172.17.0.2:3017 \
    --certificate-expiry "$(date --rfc-2822 -d 'now + 100 days')" \
    --css-file runtime-manager/css-sgx.bin \
    --certificate veracruz-mcu-client/example/controller-cert.pem \
    --capability "audio-event-triangulation.wasm:w,output:r" \
    --certificate veracruz-mcu-client/example/mcu0-cert.pem \
    --capability "input-0:w" \
    --certificate veracruz-mcu-client/example/mcu1-cert.pem \
    --capability "input-1:w" \
    --certificate veracruz-mcu-client/example/mcu2-cert.pem \
    --capability "input-2:w" \
    --binary audio-event-triangulation.wasm=veracruz-mcu-client/example/audio-event-triangulation.wasm \
    --capability "input-0:r,input-1:r,input-2:r,output:w" \
    --output-policy-file veracruz-mcu-client/example/policy.json
```

Create the Proxy Attestation Server database:

``` bash server
$ ./test-collateral/populate-test-database.sh veracruz-mcu-client/example/pas.db
```

Launch the Proxy Attestation Server:

``` bash server
$ pkill vc-pas || true
$ RUST_LOG=debug \
    vc-pas veracruz-mcu-client/example/policy.json \
        --database-url=veracruz-mcu-client/example/pas.db \
        --ca-cert=veracruz-mcu-client/example/ca-cert.pem \
        --ca-key=veracruz-mcu-client/example/ca-key.pem &
$ sleep 10
```

And launch the Veracruz Server:

``` bash server
$ pkill vc-server || true
$ RUST_LOG=debug \
    vc-server veracruz-mcu-client/example/policy.json &
$ sleep 10
```

Once you see the Veracruz Server and Proxy Attestation Server running
you can move on to running the demo


## Run the MCU client

The MCU client runs inside its own docker container, which can be spun
up using the MCU client's Makefile:

``` bash
$ make -C veracruz-mcu-client docker
```

This sets up the Zephyr build system and necessary networking interfaces
to simulate an MCU's IP stack.

Before we run the MCU client, we need to generate the policy.h and policy.c
files for our demo:

``` bash client
$ ./policy_to_header.py example/policy.json \
    --header=policy.h \
    --source=policy.c \
    --identity=example/mcu0-cert.pem \
    --key=example/mcu0-key.pem
```

Now we can run the MCU client demo:

``` bash client
$ make clean build run
```

Of course, what is triangulation without at least three reference points. This
demo includes a set of "clap" audio events which can be selected using
the CLAP variable:

``` bash client
$ ./policy_to_header.py example/policy.json \
    --header=policy.h \
    --source=policy.c \
    --identity=example/mcu1-cert.pem \
    --key=example/mcu1-key.pem
$ make clean build run CLAP=1
```

``` bash client
$ ./policy_to_header.py example/policy.json \
    --header=policy.h \
    --source=policy.c \
    --identity=example/mcu2-cert.pem \
    --key=example/mcu2-key.pem
$ make clean build run CLAP=2
```

