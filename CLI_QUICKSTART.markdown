# Getting started with the Veracruz command-line interface

This document walks through running an example Veracruz program using
the Veracruz command-line interface.

It assumes you have walked through the steps in [BUILD_INSTRUCTIONS.markdown](BUILD_INSTRUCTIONS.markdown).

So do that first and make sure the tests are passing! The rest of this
walkthrough will assume you're in a docker container capable of building
Veracruz.

## Building the Veracruz binaries

First let's make sure we've built and installed the Veracruz binaries. For
this part you need to specify which Trusted Execution Environment (TEE) you are
using. So for example, if you are running Veracruz on Linux, you would
run `make -C workspaces linux-install`.

``` bash
$ make -C workspaces linux
$ sudo make -C workspaces linux-install
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

The rust-examples are a part of the `applications` workspace in the workspaces
directory, so we need to use the `workspaces/applications` Cargo.toml. Note we
are compiling to WebAssembly here, which Rust makes very easy for us:

``` bash
$ cargo build \
    --manifest-path=workspaces/applications/Cargo.toml \
    --target wasm32-wasi \
    --release \
    --package shamir-secret-sharing
```

You should now find the example compiled to WebAssembly in the `target/wasm32-wasi/release`
directory. This will be our program to execute inside a Veracruz enclave:

``` bash
$ sdk/wasm-checker/wabt/bin/wasm-objdump \
    -d workspaces/applications/target/wasm32-wasi/release/shamir-secret-sharing.wasm \
    | head -n20 || [ $? -eq 141 ]

shamir-secret-sharing.wasm:     file format wasm 0x1

Code Disassembly:

000417 func[10] <__wasm_call_ctors>:
 000418: 10 cf 01                   | call 207 <__wasilibc_populate_preopens>
 00041b: 0b                         | end
00041d func[11] <undefined_weak:__wasilibc_find_relpath_alloc>:
 00041e: 00                         | unreachable
 00041f: 0b                         | end
000421 func[12] <_start>:
 000422: 01 7f                      | local[0] type=i32
 000424: 02 40                      | block
 000426: 10 ad 80 80 80 00          |   call 45 <__original_main>
 00042c: 22 00                      |   local.tee 0
 00042e: 45                         |   i32.eqz
 00042f: 0d 00                      |   br_if 0
 000431: 20 00                      |   local.get 0
 000433: 10 d5 81 80 80 00          |   call 213 <exit>
```

Lets go ahead and copy this to an example directory to make the paths a bit
easier to use:

``` bash
$ mkdir -p example
$ cp workspaces/applications/target/wasm32-wasi/release/shamir-secret-sharing.wasm example/example-binary.wasm
```

## Generating certificates

Identities in Veracruz are specified by a private RSA key and signed
x509 certificate.

In practice, a single identity can have many roles, but for our example
we're going to create a separate identity for the program provider, result
reader, and three data providers:

``` bash
$ openssl genrsa 2048 \
    | openssl pkcs8 -nocrypt -traditional \
    > example/example-program-key.pem
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-program-key.pem \
    -out example/example-program-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa 2048 \
    | openssl pkcs8 -nocrypt -traditional \
    > example/example-data0-key.pem
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-data0-key.pem \
    -out example/example-data0-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa 2048 \
    | openssl pkcs8 -nocrypt -traditional \
    > example/example-data1-key.pem
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-data1-key.pem \
    -out example/example-data1-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa 2048 \
    | openssl pkcs8 -nocrypt -traditional \
    > example/example-data2-key.pem
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-data2-key.pem \
    -out example/example-data2-cert.pem \
    -config test-collateral/cert.conf

$ openssl genrsa 2048 \
    | openssl pkcs8 -nocrypt -traditional \
    > example/example-result-key.pem
$ openssl req -new -x509 -sha256 -nodes -days 3650 \
    -key example/example-result-key.pem \
    -out example/example-result-cert.pem \
    -config test-collateral/cert.conf
```

And since the Proxy Attestation Server acts as a certificate authority,
we also need to provide it with its own identity:

``` bash
$ openssl ecparam -name prime256v1 -genkey -noout \
    -out example/example-ca-key.pem
$ openssl req -new -x509 -sha256 -nodes -days 1825 \
    -subj "/C=Mx/ST=Veracruz/L=Veracruz/O=Veracruz/OU=Proxy/CN=VeracruzProxyServer" \
    -key example/example-ca-key.pem \
    -out example/example-ca-cert.pem \
    -config test-collateral/ca-cert.conf
```

## Creating a policy file

Veracruz is governed by what is called a policy file. This is a json document
agreed on by all parties that indicates who has permission to provide/access
programs and data involved in a given computation.

Veracruz provides the `vc-pgen`/`generate-policy` tool to help create policy
files.  We need to provide the identities and roles of all parties involved in
the computation, the URLs for the proxy-attestation and Veracruz servers (we'll
use localhost for now), and a hash of the WebAssembly file we plan to execute.

``` bash
$ vc-pgen \
    --proxy-attestation-server-ip 127.0.0.1:3010 \
    --proxy-attestation-server-cert example/example-ca-cert.pem \
    --veracruz-server-ip 127.0.0.1:3017 \
    --certificate-expiry "$(date --rfc-2822 -d 'now + 100 days')" \
    --css-file workspaces/linux-runtime/css-linux.bin \
    --certificate example/example-program-cert.pem \
    --capability "/program/:w" \
    --certificate example/example-data0-cert.pem \
    --capability "/input/:w" \
    --certificate example/example-data1-cert.pem \
    --capability "/input/:w" \
    --certificate example/example-data2-cert.pem \
    --capability "/input/:w" \
    --certificate example/example-result-cert.pem \
    --capability "/program/:r,/output/:r" \
    --binary /program/example-binary.wasm=example/example-binary.wasm \
    --capability "/input/:r,/output/:w" \
    --output-policy-file example/example-policy.json
```

This should create a policy.json file at `example/example-policy.json`:

``` bash
$ ls example/example-policy.json
example/example-policy.json
```

NOTE! This command needs to be rerun after every recompile, since this will
change the runtime hashes.

## Running the Proxy Attestation Server

Veracruz's Proxy Attestation Server provides a frontend for a database of
attested Veracruz instances populated by the native attestation server.
This allows a client to verify through the server's certificate chain that
a Veracruz instance is what it says it is.

Before we can launch the Proxy Attestation Server,  we need to populate the
Proxy Attestation Server's database with the hashes of the Veracruz runtimes:

``` bash
$ ./test-collateral/populate-test-database.sh example/example-pas.db
```

NOTE! This command needs to be rerun after every recompile, since this will
change the runtime hashes.

Now we can launch the Proxy Attestation Server with the
`vc-pas`/`proxy-attestation-server` command. Note we are using the bash
character `&` to launch the Proxy Attestation Server in the background:

``` bash
$ vc-pas :3010 \
    --database-url=example/example-pas.db \
    --ca-cert=example/example-ca-cert.pem \
    --ca-key=example/example-ca-key.pem &
Proxy Attestation Server running on 127.0.0.1:3010
$ sleep 5
```

## Running the Veracruz Server

The Veracruz Server is the main frontend for the compute side of Veracruz. It
launches the Root Enclave (the trusted core of Veracruz) inside the enclave and
provides a Rest API for communicating into the enclave.

There is a lot of complexity underneath the hood, but launching the Veracruz
Server requires only one command. Note again we are launching the Veracruz
Server in the background:

``` bash
$ vc-server example/example-policy.json &
Veracruz Server running on 127.0.0.1:3017
$ sleep 10
```

## Running the Veracruz Client 

In practice you may integrate the `veracruz-client` Rust crate directly into
your application, sending data programatically via the Rust API, but for this
example we'll use the Veracruz Client CLI interface. This provides the same
functionality, but in a CLI form.

First let's send over the program to our Veracruz server. This requires an
identity with the "ProgramProvider" role:

``` bash
$ vc-client example/example-policy.json \
    --identity example/example-program-cert.pem \
    --key example/example-program-key.pem \
    --program /program/example-binary.wasm=example/example-binary.wasm
Loaded policy example/example-policy.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3017
Submitting <enclave>/example-binary.wasm from example/example-binary.wasm
```

Then let's send over our data with identities with the "DataProvider" role.
These are shares I've created that the example will use to reconstruct a
secret message. Keep in mind most likely this data will be coming from
different devices:

``` bash
$ vc-client example/example-policy.json \
    --identity example/example-data0-cert.pem \
    --key example/example-data0-key.pem \
    --data /input/shamir-0.dat=<(echo "01dc061a7bdaf77616dd5915f3b4" | xxd -r -p)
Loaded policy example/example-policy.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3017
Submitting <enclave>/input/shamir-0.dat from /dev/fd/63

$ vc-client example/example-policy.json \
    --identity example/example-data1-cert.pem \
    --key example/example-data1-key.pem \
    --data /input/shamir-1.dat=<(echo "027f38e27b5a02a288d064965364" | xxd -r -p)
Loaded policy example/example-policy.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3017
Submitting <enclave>/input/shamir-1.dat from /dev/fd/63

$ vc-client example/example-policy.json \
    --identity example/example-data2-cert.pem \
    --key example/example-data2-key.pem \
    --data /input/shamir-2.dat=<(echo "03eb5b946cefd583f17f51e781da" | xxd -r -p)
Loaded policy example/example-policy.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3017
Submitting <enclave>/input/shamir-2.dat from /dev/fd/63
```

And finally, we can request a computation and read the result using an identity
with the "RequestResult" role:

``` bash
$ vc-client example/example-policy.json \
    --identity example/example-result-cert.pem \
    --key example/example-result-key.pem \
    --compute /program/example-binary.wasm \
    --result /output/shamir.dat=-
Loaded policy example/example-policy.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3017
Requesting compute of <enclave>/example-binary.wasm
Reading <enclave>/output/shamir.dat into <stdout>
Hello World!
Shutting down enclave
```

Note that `--result /output/shamir.dat=-` indicates that the output
should be written to stdout.

And that's it! You've now completed a confidential computation. Only the
original creator of the shares and the result reader had the permission and
ability to observe this secret message.

## Cleanup

If we are done running computations, we can take down the Veracruz servers
with a pkill command:

``` bash
$ pkill vc-server
$ pkill vc-pas
```

