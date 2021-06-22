# Getting started with Veracruz

This document walks through running an example Veracruz program.

It assumes you have walked through the steps in [BUILD_INSTRUCTIONS.md](BUILD_INSTRUCTIONS.md).

So do that first and make sure the tests are passing! The rest of this
walkthrough will assume you're in a docker container capable of building
Veracruz.

## Building the Veracruz binaries

First lets make sure we've built and installed the Veracruz binaries. For
this part you need to specify which Trusted Execution Environment (TEE) you are
using. So for example, if you are running Veracruz on SGX, you would
run `make sgx-cli-install`, if you are using TrusteZone, you would
run `make trustzone-cli-install`.

We're also going to need a WebAssembly toolchain to build our example binary.
This can be built using `make sdk`. Fortunately, you can combine these two
rules, allowing you to maximize the time you have to get coffee while the code
is compiling:

``` bash
$ make sgx-cli-install sdk
...
```

You should now have the Veracruz binaries installed:

``` bash
$ vc-client --help
veracruz-client 0.3.0

USAGE:
    vc-client [FLAGS] [OPTIONS] <policy-path> --identity <identity> --key <key> --target <target>

...
```

Veracruz contains several independent components that are available as
separate binaries:

- `vc-pgen`/`generate-policy` - Generates and validates policy files
  used to describe a Veracruz computation.
- `vc-pas`/`proxy-attestation-server` - Runs the Veracruz proxy-attestation
  server, which is used to attest Veracruz server instances.
- `vc-server`/`veracruz-server` - Runs the Veracruz server, which provides a
  trusted, attestable enclave for Veracruz computation.
- `vc-client`/`veracruz-client` - Communicates with the Veracruz server using
  an identity's certificate to upload/download data and programs for
  computation.
- `vc-fee`/`freestanding-execution-environment` - Provides a freestanding
  execution environment that can be used to test Veracruz programs without
  needing the full attestation/TEE framework.
- `vc-wc`/`wasm-checker` - Checks that a Veracruz program is able to run in
  a Veracruz computation.

## Building the example

For this walkthrough we're going to use the Shamir secret sharing example,
which can be found in the `sdk/rust-examples/shamir-secret-sharing`
directory.

We need to use Xargo to cross-compile this example into WebAssembly, fortunately
this is all captured in the example's Makefile:

``` bash
$ cd sdk/rust-examples/shamir-secret-sharing
$ make
...
```

You should now find the example compiled to WebAssembly in the `target/wasm32-wasi/release`
directory. This will be our program to execute inside a Veracruz enclave:

``` bash
$ ls target/wasm32-wasi/release/shamir-secret-sharing.wasm
target/wasm32-wasi/release/shamir-secret-sharing.wasm
```

Lets go ahead and copy this to an example directory to make the paths a bit
easier to use:

``` bash
$ mkdir example
$ cp sdk/rust-examples/shamir-secret-sharing/target/wasm32-wasi/release/shamir-secret-sharing.wasm example/example-binary.wasm
```

<!-- TODO run example with freestanding-execution-environment? -->

## Generating certificates

Identities in Veracruz are specified by a private RSA key and signed
x509 certificate.

In practice, a single identity can have many roles, but for our example
we're going to create a separate identity for the program provide, result
reader, and three data providers:

``` bash
$ openssl genrsa -out example/example-program-key.pem 2048
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-program-key.pem \
    -out example/example-program-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa -out example/example-data0-key.pem 2048
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-data0-key.pem \
    -out example/example-data0-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa -out example/example-data1-key.pem 2048
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-data1-key.pem \
    -out example/example-data1-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa -out example/example-data2-key.pem 2048
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-data2-key.pem \
    -out example/example-data2-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa -out example/example-result-key.pem 2048
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-result-key.pem \
    -out example/example-result-cert.pem \
    -config test-collateral/cert.conf
```

## Creating a policy file

Veracruz is governed by what is called a policy file. This is a json document
agreed on by all parties that indicates who has permission to provide/access
programs and datas involved in a given computation.

Veracruz provides the `vc-pgen`/`generate-policy` tool to help create policy
files.  We need to provide the identities and roles of all parties involved in
the computation, the URLs for the proxy-attestation and Veracruz servers (we'll
use localhost for now), and a hash of the WebAssembly file we plan to execute.

``` bash
$ vc-pgen \
    --proxy-attestation-server-ip 127.0.0.1:3010 \
    --veracruz-server-ip 127.0.0.1:3017 \
    --certificate-expiry "$(date --rfc-2822 -d 'now + 100 days')" \
    --css-file runtime-manager/css.bin \
    --certificate example-program-cert.pem \
    --capability "example-binary.wasm:wx" \
    --certificate example-data0-cert.pem \
    --capability "input-0:w" \
    --certificate example-data1-cert.pem \
    --capability "input-1:w" \
    --certificate example-data2-cert.pem \
    --capability "input-2:w" \
    --certificate example-result-cert.pem \
    --capability "output:r" \
    --binary example-binary.wasm:example/example-binary.wasm \
    --capability "input-0:r,input-1:r,input-2:r,output:w" \
    --output-policy-file example/example-policy.json
```

This should create a policy.json file at `example/example-policy.json`:

``` bash
$ ls example/example-policy.json
example/example-policy.json
```

## Running the Proxy Attestation Server

Veracruz's Proxy Attestation Server provides a frontend for a database of
attested Veracruz instances populated by the native attestation server.
This allows a client to test that a Veracruz instance is what it says it is.

The Proxy Attestation Server uses an SQLite database. As a part of compilation,
the proxy-attestation-server crate generates an empty database with the correct
tables we can use for this examples.

You can launch the Proxy Attestation Server with the
`vc-pas`/`proxy-attestation-server` command. Note we are using the bash
character `&` to launch the Proxy Attestation Server in the background:

``` bash
$ vc-pas example/example-policy.json --database-url=proxy-attestation-server/proxy-attestation-server.db &
[2021-02-12T00:23:33Z INFO  proxy_attestation_server] Loaded policy 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
[2021-02-12T00:23:33Z INFO  proxy_attestation_server] Using database "proxy-attestation-server/proxy-attestation-server.db"
[2021-02-12T00:23:33Z INFO  actix_server::builder] Starting 12 workers
[2021-02-12T00:23:33Z INFO  actix_server::builder] Starting "actix-web-service-127.0.0.1:3010" service on 127.0.0.1:3010
[2021-02-12T00:23:33Z INFO  proxy_attestation_server] Proxy Attestation Server running on 127.0.0.1:3010
```

## Running the Veracruz Server

The Veracruz Server is the main frontend for the compute side of Veracruz. It
launches the Root Enclave (the trusted core of Veracruz) inside the enclave and
provides a Rest API to communicating into the enclave.

There is a lot of complexity underneath the hood, but launching the Veracruz
Server requires only one command. Note again we are launching the Veracruz
Server in the background:

``` bash
$ vc-server example/example-policy.json &
[2021-02-12T00:55:40Z INFO  veracruz_server] Loading policy "example/example-policy.json"
[2021-02-12T00:55:40Z INFO  veracruz_server] Loaded policy 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
[2021-02-12T00:55:44Z INFO  actix_web::middleware::logger] 127.0.0.1:54762 "POST /Start HTTP/1.1" 200 96 "-" "-" 0.000542
[2021-02-12T00:55:44Z INFO  actix_web::middleware::logger] 127.0.0.1:54764 "POST /SGX/Msg1 HTTP/1.1" 200 312 "-" "-" 0.233101
[2021-02-12T00:55:45Z INFO  actix_web::middleware::logger] 127.0.0.1:54768 "POST /SGX/Msg3 HTTP/1.1" 200 25 "-" "-" 0.695685
[2021-02-12T00:55:45Z INFO  actix_server::builder] Starting 12 workers
[2021-02-12T00:55:45Z INFO  actix_server::builder] Starting "actix-web-service-127.0.0.1:3017" service on 127.0.0.1:3017
[2021-02-12T00:55:45Z INFO  veracruz_server] Veracruz Server running on 127.0.0.1:3017
```

## Running the Veracruz Client 

In practice you may integrate the `veracruz-client` Rust crate directly into
your application, sending data programatically via the Rust API, but for this
example we'll use the Veracruz Client CLI interface. This provides the same
functionality, but in a CLI form.

First lets send over the program to our Veracruz server, this requires an
identity with the "PiProvider" role:

``` bash
$ ./bin/vc-client example/example-policy.json \
    --key example/example-program-key.pem \
    --identity example/example-program-cert.pem \
    --program example-binary.wasm:example/example-binary.wasm
[2021-02-12T01:27:18Z INFO  veracruz-client] Loading policy "example/example-policy.json"
[2021-02-12T01:27:18Z INFO  veracruz-client] Loaded policy 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
...
[2021-02-12T01:27:18Z INFO  veracruz-client] Submitted program "example/example-binary.wasm"
```

Then lets send over our datas with identities with the "DataProvider" role.
These are shares I've created that the example will use to reconstruct a
secret message. Keep in mind most likely these datas will be coming from
different devices:

``` bash
$ ./bin/vc-client example/example-policy.json \
    --key example/example-data0-key.pem \
    --identity example/example-data0-cert.pem \
    --data input-0:<(echo "018b76552fa61d7f7661d2119b" | xxd -r -p)
[2021-02-12T01:27:18Z INFO  veracruz-client] Loading policy "example/example-policy.json"
[2021-02-12T01:27:18Z INFO  veracruz-client] Loaded policy 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
...
[2021-02-12T01:27:18Z INFO  veracruz-client] Submitted data "/dev/fd/63"

$ ./bin/vc-client example/example-policy.json \
    --key example/example-data1-key.pem \
    --identity example/example-data1-cert.pem \
    --data input-1:<(echo "02063622071451f67d6b00e602" | xxd -r -p)
[2021-02-12T01:36:35Z INFO  veracruz-client] Loading policy "example/example-policy.json"
[2021-02-12T01:36:35Z INFO  veracruz-client] Loaded policy 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
...
[2021-02-12T01:36:35Z INFO  veracruz-client] Submitted data "/dev/fd/63"

$ ./bin/vc-client example/example-policy.json \
    --key example/example-data2-key.pem \
    --identity example/example-data2-cert.pem \
    --data input-2:<(echo "03c5251b44dd6cde6478be93b8" | xxd -r -p)
[2021-02-12T01:37:58Z INFO  veracruz-client] Loading policy "example/example-policy.json"
[2021-02-12T01:37:58Z INFO  veracruz-client] Loaded policy 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
...
[2021-02-12T01:37:58Z INFO  veracruz-client] Submitted data "/dev/fd/63"
```

And finally, we can request the result using an identity with the
"RequestResult" role:

``` bash
$ ./bin/vc-client example/example-policy.json \
    --key example/example-result-key.pem \
    --identity example/example-result-cert.pem \
    --output example-binary.wasm:-
[2021-02-12T01:40:21Z INFO  veracruz-client] Loading policy "example/example-policy.json"
[2021-02-12T01:40:21Z INFO  veracruz-client] Loaded policy 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
...
[2021-02-12T01:40:21Z INFO  veracruz-client] Read results into "-"
[2021-02-12T01:40:21Z INFO  veracruz-client] Shutdown server
Hello World!
```

And that's it! You've now completed a confidential computation. Only the
original creator of the shares and the result reader had the permission and
ability to observe this secret message.

