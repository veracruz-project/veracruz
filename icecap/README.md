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

To instead build a test system for the Raspberry Pi 4, do:

```
cd /work/veracruz/icecap # back inside the container
make clean
make test-system ICECAP_PLAT=rpi4
ls -L ./result/boot/
```

For more detailed information about supported Raspberry Pi 4 variants and about running the test system contained in `./result/boot/`, see https://gitlab.com/arm-research/security/icecap/icecap.
