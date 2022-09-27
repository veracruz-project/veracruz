# Veracruz: privacy-preserving collaborative compute

![CI build status](https://github.com/veracruz-project/veracruz/actions/workflows/main.yml/badge.svg)

<img src = "https://confidentialcomputing.io/wp-content/uploads/sites/85/2019/08/cc_consortium-color.svg" width=192>

## About

Veracruz is now an adopted project of the [Confidential Compute Consortium (CCC)](https://confidentialcomputing.io).

Veracruz is a framework for defining and deploying collaborative, privacy-preserving computations amongst a group of mutually mistrusting individuals.
Some potential use-cases for Veracruz include:

* Privacy-preserving collaborative machine learning,
* Privacy-preserving delegated computations from a computationally weak device to a more capable (but potentially untrusted) edge device or server,
* Secret auctions, elections or polls, surveys,
* ...and many more.

Veracruz uses *strong isolation* technology (a mixture of *trusted hardware* and high-assurance *hypervisor-based* isolation), along with  *remote attestation protocols*, to establish a safe, "neutral ground" within which a collaborative computation takes place on an untrusted device.
Concretely, Veracruz computations are special-purpose *WebAssembly* binaries, compiled against a small SDK which we provide.
WebAssembly acts both as a sandbox, pinning down the behaviour of the program, and allows us to abstract over the different strong isolation technologies that we support.

To learn more about Veracruz, the motivation, design, use-cases, and so on, please read the [Veracruz project wiki](https://github.com/veracruz-project/veracruz/wiki) or dive in and start playing with Veracruz using [our Docker container](https://github.com/veracruz-project/veracruz-docker-image).
The latest project news is available on the [Veracruz project homepage](https://veracruz-project.github.io).

To jump straight into the codebase, please read the growing number of guides we have on how to get started with Veracruz:
- [BUILD_INSTRUCTIONS.markdown](BUILD_INSTRUCTIONS.markdown) - Set up a build environment for Veracruz
- [CLI_QUICKSTART.markdown](CLI_QUICKSTART.markdown) - Quickly run Veracruz with a prepared demo program

## Security disclaimer
As of September 27th, 2022, due to an [entropy bug presumably affecting AWS Nitro enclaves](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/issues/15), our Nitro backend relies on a temporary workaround for RNG. More specifically, Mbed TLS' RNG has been changed to return an array of all zeroes. This is a temporary workaround that will be removed when the root cause is fixed by AWS.

## News

- **May 2022**: we have released Veracruz 22.05 (see the `veracruz-2205` Git tag).  See `documents/release-notes/VERACRUZ-2205.markdown` for notable changes in this release.
- **May 2022**: we have released a technical report on the Veracruz and IceCap projects, hosted on [Arxiv](https://arxiv.org/abs/2205.03322).
- **April 2022**: we have released Veracruz 22.04 (see the `veracruz-2204` Git tag).  See `documents/release-notes/VERACRUZ-2204.markdown` for notable changes in this release.

## Get involved!

The Veracruz team welcome new collaborators and contributions!
We maintain a list of open issues, ideas for new features, and possible improvements that can be made to Veracruz in our issue tracker, but also welcome ideas for new features and improvements from contributors, too.
Many issues in our issue tracker are marked as being suitable for new contributors to the project.

Veracruz maintains a public Slack channel for discussion about the project under the Confidential Compute Consortium's workspace.
You can access this channel [here](https://join.slack.com/t/confidentialcomputing/shared_invite/zt-wmtekhvm-zXF_U1b5AtRpt~0cZTJgbQ).
Anybody and everybody is welcome to join to meet the team and discuss the project!

We also have a weekly open Zoom meeting that you are welcome to join which is held every Thursday, 15:00 (BST) / 10:00 (CDT), and last for an hour.
You can join with [this](https://armltd.zoom.us/j/98953009653?pwd=WVhqKzZOaDRWb2F5OTlpbzgyN2tnZz09) link.
Come along and meet the team, find out what everybody is working on, and discuss ideas for improving Veracruz!

## Citing Veracruz

If you use Veracruz or otherwise wish to discuss the project, please cite the project as follows:

```
@techreport {
  author = {Brossard, Mathias and Bryant, Guilhem and El Gaabouri, Basma and Fan, Xinxin and Ferreira, Alexandre and Grimley-Evans, Edmund and Haster, Christopher and Johnson, Evan and Miller, Derek and Mo, Fan and Mulligan, Dominic P. and Spinale, Nick and van Hensbergen, Eric and Vincent, Hugo J. M. and Xiong, Shale},
  title = {Private delegated computations using strong isolation},
  institution = {Systems Research Group, Arm Research},
  doi = {https://doi.org/10.48550/arXiv.2205.03322},
  type = {Technical report},
  pages = {20},
  year = {2022}
}
```

## License

This project's codebase is licensed under the [MIT license](LICENSE_MIT.markdown).

We use the image [Veracruz Puerto - Vista desde el Hotel Emporio](sdk/data-generators/image-processing-generator/veracruz.jpg) by Eduardo Pavon as a test dataset for some of our examples.  This image is licensed under the [Creative Commons Attribution Share Alike 2.0 Generic (CC-BY-SA 2.0) license](LICENSE_CC-BY-SA-2.0.markdown).
