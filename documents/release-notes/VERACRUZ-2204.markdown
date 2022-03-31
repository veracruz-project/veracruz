# Release notes for Veracruz 22.04

Notable changes in this release:

- Changes to Linux and IceCap attestation, bringing them in line with attestation for the Nitro platform.
Policies are now provisioned into the running isolate much later in the attestation process, as opposed to being provisioned in the opening message of the attestation protocol.
- Workspace Cargo.lock files are now included in the Veracruz repository.
This should prevent a class of build issues with dependencies silently updating their MSRV without a version bump, as well as making builds more reproducible.
- The Linux Root Enclave has now been removed, bringing the component diagram for Linux inline with Nitro and IceCap.
This was the last root enclave to be removed.
- A new Veracruz system call, `fd_create`, has been added for creating anonymous files.
This sits outside of the WASI namespace, and requires the (re)introduction of the `libveracruz` programming support library.
- Optimisations in the networking stack were applied, which should go some way to reducing latency in communication between Veracruz clients and servers.

...plus other smaller refactorings and bug fixes.
