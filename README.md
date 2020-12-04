## Mini-Durango

Need to add more here...

## How to build

At the moment, Mini-Durango runs inside QEMU inside a Docker instance.

First build/run Docker:

``` bash
make docker
```

Then, build/run the Mini-Durango client:

``` bash
make build run
```

If everything goes well, you should see QEMU run and print something:

``` bash
*** Booting Zephyr OS build zephyr-v2.4.0  ***
blah blah blah
```
