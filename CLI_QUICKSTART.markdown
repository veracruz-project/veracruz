# A quick start using the Veracruz command-line interface

This document is a quick overview on how to use the Veracruz command-line
interface using artifacts built during testing as a part of the
test-collateral.

For a more in-depth guide on how to use Veracruz and how to manually generate
the necessary artifacts, see [CLI_INSTRUCTIONS.markdown](CLI_INSTRUCTIONS.markdown).

This document assumes you have walked through the steps in
[BUILD_INSTRUCTIONS.markdown](BUILD_INSTRUCTIONS.markdown), and have a working
build environment.

## Building the Veracruz binaries

First thing is we need to build the actual Veracruz command-line interfaces,
a WebAssembly toolchain, and the test-collateral artifacts. These can be
compiled using make, however we need to specify which Trusted Execution
Environment (TEE) we are building for. So for example, if you are running
Veracruz on SGX, you would run `make sgx-cli-install`, if you are using
TrustZone, you would run `make trustzone-cli-install`.

These can be combined into one command to maximize the time you have to
make coffee while the code is compiling:

``` bash
$ make sdk sgx-cli-install sgx-test-collateral
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

## Running the Proxy Attestation Server and Veracruz Server

First we need to launch the Proxy Attestation Server using the `vc-pas` program:

``` bash
$ vc-pas :3010 \
    --database-url=test-collateral/proxy-attestation-server.db \
    --ca-cert=test-collateral/CACert.pem \
    --ca-key=test-collateral/CAKey.pem &
Proxy Attestation Server running on 127.0.0.1:3010
$ sleep 10
```

Now we can launch the Veracruz Server using the `vc-server` program:

``` bash
$ vc-server test-collateral/triple_policy_1.json &
Veracruz Server running on 127.0.0.1:3021
$ sleep 10
```

## Running the Veracruz Clients

At this point we have set up Veracruz with a policy allowing computation of a
Shamir's secret sharing demo. To perform the actual computation, we need
the binary (who is hashed as a part of the policy file), and the shares to
decode. Currently this demo is configured to decode 3 shares.

The identity of each client is determined by a signed certificate, and the
permissions each client has is stored in the policy file.

``` bash
$ vc-client test-collateral/triple_policy_1.json \
    --identity test-collateral/program_client_cert.pem \
    --key test-collateral/program_client_key.pem \
    --program /program/shamir-secret-sharing.wasm=test-collateral/shamir-secret-sharing.wasm
Loaded policy test-collateral/triple_policy_1.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3021
Submitting <enclave>/shamir-secret-sharing.wasm from test-collateral/shamir-secret-sharing.wasm
```

``` bash
$ vc-client test-collateral/triple_policy_1.json \
    --identity test-collateral/data_client_cert.pem \
    --key test-collateral/data_client_key.pem \
    --data /input/shamir-0.dat=<(cat test-collateral/share-1.dat | xxd -r -p)
Loaded policy test-collateral/triple_policy_1.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3021
Submitting <enclave>/input/shamir-0.dat from /dev/fd/63
```

``` bash
$ vc-client test-collateral/triple_policy_1.json \
    --identity test-collateral/data_client_cert.pem \
    --key test-collateral/data_client_key.pem \
    --data /input/shamir-1.dat=<(cat test-collateral/share-2.dat | xxd -r -p)
Loaded policy test-collateral/triple_policy_1.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3021
Submitting <enclave>/input/shamir-1.dat from /dev/fd/63
```

``` bash
$ vc-client test-collateral/triple_policy_1.json \
    --identity test-collateral/data_client_cert.pem \
    --key test-collateral/data_client_key.pem \
    --data /input/shamir-2.dat=<(cat test-collateral/share-3.dat | xxd -r -p)
Loaded policy test-collateral/triple_policy_1.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3021
Submitting <enclave>/input/shamir-2.dat from /dev/fd/63
```

We can request a computation as long as we have read access to the program we
want to execute:

``` bash
$ vc-client test-collateral/triple_policy_1.json \
    --identity test-collateral/program_client_cert.pem \
    --key test-collateral/program_client_key.pem \
    --compute /program/shamir-secret-sharing.wasm
Loaded policy test-collateral/triple_policy_1.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3021
Requesting compute of <enclave>/program/shamir-secret-sharing.wasm
```

And finally, we can get request the result, as long as our client certificate
has the permission to do so:

``` bash
$ vc-client test-collateral/triple_policy_1.json \
    --identity test-collateral/result_client_cert.pem \
    --key test-collateral/result_client_key.pem \
    --result /output/shamir.dat=-
Loaded policy test-collateral/triple_policy_1.json 645ae94ea86eaf15cfc04c07a17bd9b6a3b3b6c3558fae6fb93d8ee4c3e71241
Connecting to 127.0.0.1:3021
Reading <enclave>/output/shamir.dat into <stdout>
Hello World!
Shutting down enclave
```

For more info on these commands and how to build the artifacts,
see [CLI_INSTRUCTIONS.markdown](CLI_INSTRUCTIONS.markdown).

## Cleanup

When you are done with the computation, the servers can be shutdown using pkill:

``` bash
$ pkill vc-server
$ pkill vc-pas
```
