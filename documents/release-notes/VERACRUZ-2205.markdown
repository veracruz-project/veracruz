# Release notes for Veracruz 22.05

Notable changes in this release (see the Git tag `veracruz-2205`):

- We welcomed several new contributors to the project: Aryan Godara, Mohamed Abdelfatah, and Sagar Arya.  We thank all for their contributions!
- Several new examples were added to the SDK, including a text search and a Huffman encoding example.
- Support for linear pipelines of functions was added to Freestanding Execution Engine, to execute several programs in turn, one after the other.
- The RuntimeManager{Request, Response} types were unified across all backends, making attestation for IceCap, Arm CCA, and AWS Nitro more uniform.
- The shutdown mechanism was fixed and made simpler for AWS Nitro.
- Improved documentation, including bringig the CLI quickstart documentation back up-to-date, and clearly documenting all IP addresses and ports used by Veracruz.
- The IceCap platform was changed to support seL4 as an in-Realm OS.
- Various dependencies, including RusTLS, WebPKI, Ring, Regex, Rand, and Nix were updated, many of which to fix security vulnerabilities spotted by Dependabot.

...plus other smaller refactorings and bug fixes.
