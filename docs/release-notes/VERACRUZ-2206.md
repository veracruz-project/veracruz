# Release notes for Veracruz 22.06

Notable changes in this release (see the Git tag `veracruz-2206`):

- We welcomed Federico Bozzini as a new contributor to the project.  Welcome Federico!
- Dominic Mulligan announced that he is stepping down as technical lead of the Veracruz project, from within Arm. Derek Miller will be taking over.
- A new "execute" right was added to our concept of filesystem rights, alongside "read" and "write", bringing us inline with standard POSIX file permissions and straying slightly from standard WASI.
- The default Veracruz build is now a faster "debug" build, rather than a full release build, which should speed up development.
- Direct use of the Ring library have now been replaced with "mbedTLS".  The full adoption of mbedTLS as our cryptography library of choice is ongoing: RusTLS has already been replaced by mbedTLs in the Veracruz Client code, in this release.
- Version bumps of Wasmi and Wasmtime, thereby adopting performance and security improvements.
- Various codebase improvements, driven by Clippy linting, adopted.
- Security fixes and other version bumps driven by Dependabot.
- Stability fixes in the IceCap/Veracruz integration.

...plus other smaller refactorings and bug fixes.
