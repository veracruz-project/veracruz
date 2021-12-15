# Veracruz on IceCap

IceCap: https://gitlab.com/arm-research/security/icecap/icecap

## Quick Start

Build and enter the Veracruz on IceCap Docker container for development:

```
cd veracruz/icecap/docker
make run && make exec
```

From inside of the container, build and run a test system emulated by QEMU,
loaded with `veracruz-test` and `veracruz-server-test`:

```
cd /work/veracruz/icecap
make run-tests
```

To instead build a test system for the Raspberry Pi 4, do:

```
cd /work/veracruz/icecap
make clean
make test-system ICECAP_PLAT=rpi4
ls -L ./build/test-system/boot/
```

After you've booted the board to a shell from the boot directory mentioned above, run the script `/run-tests` to run all tests. See `./nix/host/config.nix` or inspect `/run-tests` to discover how to test with more precision.

For more detailed information about supported Raspberry Pi 4 variants and about running the test system contained in `./build/test-system/boot/`, see https://gitlab.com/arm-research/security/icecap/icecap.

## Caveats

IceCap doesn't yet support attestation.

IceCap doesn't yet provide a source of randomness to realms. Until that changes, WASM programs running under Veracruz on IceCap are provided with a trivial generator with a fixed seed and a large period, which is not suitable for use in cryptography.
