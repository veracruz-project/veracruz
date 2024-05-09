# Veracruz: privacy-preserving collaborative compute

![CI build status](https://github.com/veracruz-project/veracruz/actions/workflows/main.yml/badge.svg)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8918/badge)](https://www.bestpractices.dev/projects/8918)

<img src = "https://confidentialcomputing.io/wp-content/uploads/sites/10/2022/07/cc_consortium-color.svg" width=192>

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

To learn more about Veracruz, the motivation, design, use-cases, and so on, please read the [Veracruz project wiki](https://github.com/veracruz-project/veracruz/wiki).
The latest project news is available on the [Veracruz project homepage](https://veracruz-project.github.io).

To jump straight into the codebase, please read the growing number of guides we have on how to get started with Veracruz:
- [Build instructions](docker/README.md) - Set up a build environment for Veracruz
- [CLI Quickstart](docs/CLI_QUICKSTART.md) - Quickly run Veracruz with a prepared demo program

## News

- **May 2023**: our paper "Private delegated computations using strong isolation" was accepted into [IEEE Transactions on Emerging Topics in Computing](https://doi.ieeecomputersociety.org/10.1109/TETC.2023.3281738).
- **June 2022**: we have released Veracruz 22.06 (see the `veracruz-2206` Git tag).  See [release notes](docs/release-notes/VERACRUZ-2206.md) for notable changes in this release.
- **May 2022**: we have released Veracruz 22.05 (see the `veracruz-2205` Git tag).  See [release notes](docs/release-notes/VERACRUZ-2205.md) for notable changes in this release.
- **May 2022**: we have released a technical report on the Veracruz and IceCap projects, hosted on [Arxiv](https://arxiv.org/abs/2205.03322).
- **April 2022**: we have released Veracruz 22.04 (see the `veracruz-2204` Git tag).  See [release notes](docs/release-notes/VERACRUZ-2204.md) for notable changes in this release.

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

Except where otherwise stated, this project's codebase is licensed under the [MIT license](LICENSE.md).
