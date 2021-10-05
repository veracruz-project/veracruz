# Veracruz on IceCap (WIP)

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
make test-system # this will take a while
./result/run
```

From inside of the test system, run `veracruz-test` and `veracruz-server-test`:

```
run_test veracruz-test
run_test veracruz-server-test
```

Use `'<ctrl>-a x'` to quit QEMU and exit the emulation.
