# Major Veracruz components, and their purpose

This document describes all of the major current Veracruz components, and their
purpose.  If adding a new component, please make sure to update this document
so that we can keep track of what everything does.

## Components of the Veracruz trusted runtime

The trusted Veracruz runtime manages data and programs, once provisioned into
the isolate, and executes the WASM binary on the secret inputs once a result is
requested by a principal.  Note that this code must be explicitly trusted by
anybody aiming to use Veracruz.  Its major components are:

- Session manager: acts as the TLS endpoint inside the isolate, managing
encrypted and integrity-protected communication sessions between the trusted
Veracruz runtime and the outside world.
- Execution Engine: is the WASM execution engine for Veracruz, and which actually
executes a program to completion (or failure!).  The Execution Engine exposes a custom
ABI to the WASM binary, and abstracts over the different execution strategies
available for executing a program: at the moment the JIT strategy is only
available when using seL4 (or `freestanding-execution-engine`---see below) with
interpretation as the only selectable execution strategy for Nitro
(we are currently working on changing this).
- Transport protocol: is a support library that manages the parsing and
serialization of `protobuf` messages used in the various Veracruz wire
protocols.
- Runtime Manager: is a "command and control" module for the trusted Veracruz
runtime which drives the other components.
- platform_services: provides an abstraction layer over important services that
each isolate implementation provides.  At the moment, this consists of a single
service: random number generation.
- veracruz-utils: miscellaneous or common code that either does not fit
elsewhere or is used by many different Veracruz components.  The most important
concept exposed by this library is the Global Policy, which describes the
"topology" of a Veracruz computation.

## Interfacing with the Veracruz trusted runtime

Untrusted code needs to be used to interface between clients and the trusted
Veracruz runtime.  Components related to this untrusted interfacing are:

- Veracruz client: is the software interacting with the Veracruz trusted
runtime.  Principals provisioning secrets into the isolate/challenging the
authenticity of the isolate with remote attestation use this for all
communication between them and the trusted runtime.  It is located in the
`veracruz-client` directory
- Veracruz server: is an untrusted "bridge"/server component executing on the
delegate's machine, outside of the isolate, and which routes encrypted
communication between the various principals and the isolate. 

## The Veracruz hybrid proxied-attestation service

Veracruz uses a custom attestation service which sits between client code and
the native attestation service of a particular enclave implementation.
It contains the following components:

- psa-attestation: support code for the Arm PSA Attestation Protocol and
Token.  This is the attestation protocol that the Veracruz attestation
service exposes to client code.
- Proxy Attestation Server: this is the attestation service proper, which
  maintains a database of registered keys and identities, and which can be contacted
  by clients to authenticate an isolate enrolled in the service.

## The Software Development Kit

The Veracruz Software Development Kit (SDK) is intended to ease writing
programs for the Veracruz platform.  It contains the following components:

- Examples: various example multi-party computations of interest, written in
Rust, have been developed as examples (they are also used in our various
integration tests: see the test plan document for more details).  The examples
include those that do not build against the Rust standard library (i.e. are
`no_std`) and those which use both the standard library and off-the-shelf Rust
libraries for e.g. machine learning.  Examples use Xargo to build a custom set
of core Rust libraries before building the examples.
- Freestanding Execution Engine: this is a version of the WASM execution
engine (see above) that has been wrapped in a command line interface, and is
intended to allow offline testing of Veracruz programs outside of an enclave.
See `./freestanding-execution-engine --help` for more information on invoking the
offline execution engine, and the different configuration options available.
- The Veracruz support library (`libveracruz`): this is a Rust support library
for writing Veracruz programs.  It abstracts the Veracruz ABI, exposing a
higher-level series of functions for grabbing inputs to the computation,
writing outputs, signalling failures, and so on and so forth.
- The Veracruz runtime library (`veracruz_rt`): this is a thin Rust runtime
library for working with `no_std` builds with Veracruz.  It sets up a global
allocator (`wee_alloc`) and helps with program teardown.
- A fork of Rust's `getrandom` and `rand` crates: these crates for sampling
random numbers, and working with distributions of random numbers, have been
ported to work with the Veracruz ABI's facilities for generating random data,
as exposed by `libveracruz`.
- A custom build target descriptor: Veracruz programs written in Rust are
compiled against the `wasm32-arm-veracruz` build target.  This is a derivative
of the `wasm32-unknown-unknown` build target, and makes the forking of
existing Rust libraries (e.g. `getrandom` and `rand` above) easier, as the
`wasm32-unknown-unknown` target is often interpreted as implying the WASI ABI
in existing Rust code.
- WASM Checker: this is an ABI-validator for Veracruz binaries, which takes a
binary as input and certifies that it only assumes the presence of WASM host
functions that are exposed by the Veracruz ABI.
