# Veracruz: privacy-preserving collaborative compute

Veracruz is a framework for defining and deploying collaborative, privacy-preserving computations amongst a group of mutually mistrusting individuals.
Some potential use-cases for Veracruz include:

* Privacy-preserving collaborative machine learning,
* Privacy-preserving delegated computations from a computationally weak device to a more capable (but potentially untrusted) edge device or server,
* Secret auctions, elections or polls, surveys,
* ...and many more.

Veracruz uses *strong isolation* technology (a mixture of *trusted hardware* and high-assurance *hypervisor-based* isolation), along with  *remote attestation protocols*, to establish a safe, "neutral ground" within which a collaborative computation takes place on an untrusted device.
Concretely, Veracruz computations are special-purpose *WebAssembly* binaries, compiled against a small SDK which we provide.
WebAssembly acts both as a sandbox, pinning down the behaviour of the program, and allows us to abstract over the different strong isolation technologies that we support.

To learn more about Veracruz, the motivation, design, use-cases, and so on, please read the Veracruz project wiki.
The latest project news is available on the [Veracruz project homepage](https://veracruz-project.github.io).

## Get involved!

The Veracruz project welcomes contributions.
We maintain a list of open issues, ideas for new features, and possible improvements that can be made to Veracruz in our issue tracker.
Many of these issues are marked as being suitable for new contributors to the project.


