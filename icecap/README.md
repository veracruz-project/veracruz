# Veracruz on IceCap

## Directory structure

These are the parts of the Veracruz source tree that are important for IceCap,
with some indications of how they depend on each other.

### `icecap/crates -> icecap/src/rust/crates`

* `runtime-manager/Cargo.toml` and `virtio-console-server/Cargo.toml`
  access `icecap/icecap/src/rust/crates` through this symbolic link.

### `icecap/icecap/`

* MODULE from https://gitlab.com/icecap-project/icecap.git
* IceCap code, mostly by Nick Spinale.
* The parts used by Veracruz are:
  * `src/c`
  * `src/python`
  * `src/rust/crates`
  * `src/rust/support`

### `icecap/src/`

* `c/libc-supplement/` has `getrandom` (**it's bogus!**), `printf`, ...
  It is built and linked in by `workspaces/icecap-runtime/Makefile`.
* `rust/icecap-wrapper/` just pulls in four crates from
  `icecap/icecap/src/rust/crates/...`. UNUSED!

### `icecap/sysroot/libc/`

* MODULE from https://gitlab.com/icecap-project/rust-libc.git,
  forked from https://github.com/rust-lang/libc.git
* The only changes are in `src/icecap.rs` and `src/lib.rs`.
* It is referenced from:
  * `icecap/sysroot/workspace/Cargo.toml`
  * `workspaces/icecap-runtime/Cargo.toml`

### `icecap/sysroot/rust/`

* MODULE from https://gitlab.com/icecap-project/rust.git,
  forked from https://github.com/rust-lang/rust.git
* The Rust source code!
* The changes for IceCap are in `library/std/`,
  plus the removal of 13 submodules to save disc space.
  The remaining submodules are unchanged from upstream.
* Only the contents of `library/` are used by Veracruz
  (and the following subdirectorires of `library/` are not used:
  `panic_unwind`, `proc_macro`, `profiler_builtins`,
  `rtstartup`, `rustc-std-workspace-std`, `test`).

### `icecap/sysroot/workspace/`

* Despite the directory name, this is not a workspace. It is a crate
  with an empty `src/lib.rs` and with `[dependencies]` and
  `[patch.crates-io]` sections that make the IceCap sysroot get built
  as a side-effect of building this crate.

* Relative paths in the `Cargo.toml` refer to these crates in the source tree:
  * `icecap/icecap/src/rust/crates/framework/std-support/icecap-std-impl`
  * `icecap/sysroot/libc`
  * `icecap/sysroot/rust/library/rustc-std-workspace-alloc`
  * `icecap/sysroot/rust/library/rustc-std-workspace-core`
  * `icecap/sysroot/rust/library/std`

### `workspaces/icecap-runtime/`

* `Cargo.toml` defines a workspace with members:
  * `crates/runtime-manager`
  * `src/virtio-console-server`

* `Makefile` builds: seL4, IceCap libraries, sysroot, Veracruz crates
  (runtime-manager and virtio-console-server), IceCap CDL, CapDL
  Loader, ELF Loader.

* `cdl/` contains Python code.

* `crates -> ../..`: Symbolic link used by `Cargo.toml` and `Makefile`.

* `icecap -> ../../icecap/icecap`: Symbolic link used by `Makefile`.

* `icecap.mk`: Included by `Makefile`.

* `mk/`: Files included by `Makefile`.

* `src/cmake-config/`: Used for seL4 and ELF Loader.

* `src/icecap-runtime-root-config.h`: Used for CapDL Loader.

* `src/virtio-console-server`: Rust crate, member of workspace.

### `workspaces/icecap-runtime/deps/capdl/`

* MODULE from https://gitlab.com/icecap-project/capdl.git,
  forked from https://github.com/seL4/capdl.git

### `workspaces/icecap-runtime/deps/seL4/`

* MODULE from https://gitlab.com/icecap-project/seL4.git,
  forked from https://github.com/seL4/seL4.git

### `workspaces/icecap-runtime/deps/seL4_tools/`

* MODULE from https://gitlab.com/icecap-project/seL4_tools.git,
  forked from https://github.com/seL4/seL4_tools.git
