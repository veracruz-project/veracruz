# Before you begin

Please make sure you read through the Veracruz FAQ available from the
Veracruz project homepage to familiarize yourself with the project, its
goals, and some of the design decisions that we have taken during the
development of the project.  You can also chat (informally) with the
Veracruz development team via our public Slack channel, where we welcome
any new, prospective contributor to the project.  Details of how to
join the Slack channel are available on the Veracruz project homepage.

Please be aware that the Veracruz project has adopted a code of conduct,
the full text of which is included below.

# Project license, and developer certificate of origin

The Veracruz codebase is licensed under the MIT open source license.
Please see the `LICENSE.markdown` file in the Veracruz repository for the
full text of this license.  New contributions are expected to be lisensed
under the MIT license.

Please note that we expect contributors to the project to self-certify
that they are authorized to contribute code using the Linux Foundation's
Developer Certificate of Origin.  See http://developercertificate.org for
more details.

# Low hanging fruit

We maintain a list of open issues and missing features in our GitHub
issue tracker.  Some of these will be marked as "low hanging fruit", and
are deemed suitable for new contributors to the project to tackle.
Attempting to resolve one (or more) of these issues first, before moving
on to larger changes, is a good way of integrating into the project and
understanding our development flow.

# Larger changes

For those wishing to tackle larger changes, it is a good idea to discuss
these ideas with the existing project contributors before beginning to
write code.  This can be done through our public Slack channel, or through
our regular (public) technical meetings on Zoom.  Details of how to join
these meetings (they are open to anybody who wishes to contribute to the
project) are available from the Veracruz homepage.

Once discussed, for larger changes, ideally an issue will be opened in
our Github issue tracker so that we can track the project's progression,
and so that pull requests and issues are tied together.

Once your proposed changes have been discussed, they can be incorporated
into the main Veracruz codebase by issuing a pull request through Github.

# Submitting pull requests

Before submitting any pull request, please ensure that:
1. You have run `cargo fmt` on any changes.  A project-wide `cargo fmt`
   can be executed by building the `fmt` target in the main project
   Makefile.
2. The new changes are clearly commented using `rustdoc` markup, for
   Rust code, or similar for whatever language your changes are written
   in.
3. The pull request is adequately documented, explaining the problem that
   it is solving, or the design changes that it is making.  Ideally pull
   requests will make reference to an issue registered in our issue
   tracker.
4. Any new features are accompanied by unit-level and integration tests.
   Please see the test plan Markdown file for information on the Veracruz
   integration tests and their purpose.  If you add more tests, please
   also update the test plan document, too, to ensure we do not duplicate
   work, and so that we can keep track of exactly what is being tested.
5. Your pull request includes a self-certifying Developer Certificate of
   Origin stating that you are authorized (by e.g. your employer) to
   contribute code to the Veracruz project.  See
   https://developercertificate.org for more details.

A reviewer will then be assigned to review the changes, and if appropriate,
mege them into the master branch.

# You've found a bug?

The procedure for bugs depends on how "security-critical" the bug is.  If
the bug is particularly severe, affecting the security of the Veracruz
framework or potential users of it, then these bugs can be reported
discreetly and directly to the Veracruz development team via a dedicated
email alias.  Please see the security disclosure Markdown file in this
repository, or the Veracruz project homepage, for more details on how a
security-critical bug can be reported.

Any other bugs can be reported publicly via our Github issue tracker.
Please ensure that you provide adequate information for a member of the
Veracruz development team to reproduce the bug, typically including a
release-tag, or Git commit hash, of whichever version of the Veracruz
codebase that you are using.

# Release cycle

Periodically, on an approximate bi-monthly cadence, we "tag" a Github
repository snapshot with a version number using Git tags.

Please note that, as Veracruz is an active research project, these tagged
snapshots of the Veracruz codebase are more intended to ease communication
with the Veracruz developers/make bug reports easier, rather than act as
stable release candidates for the Veracruz project.

# Code of conduct

The Veracruz project has adopted the Contributor Covenant Code of Conduct,
version 2.  The full text of this code of conduct is included, below.

## Contributor Covenant Code of Conduct

### Our Pledge

We as members, contributors, and leaders pledge to make participation in our
community a harassment-free experience for everyone, regardless of age, body
size, visible or invisible disability, ethnicity, sex characteristics, gender
identity and expression, level of experience, education, socio-economic status,
nationality, personal appearance, race, religion, or sexual identity
and orientation.

We pledge to act and interact in ways that contribute to an open, welcoming,
diverse, inclusive, and healthy community.

### Our Standards

Examples of behavior that contributes to a positive environment for our
community include:

* Demonstrating empathy and kindness toward other people
* Being respectful of differing opinions, viewpoints, and experiences
* Giving and gracefully accepting constructive feedback
* Accepting responsibility and apologizing to those affected by our mistakes,
  and learning from the experience
* Focusing on what is best not just for us as individuals, but for the
  overall community

Examples of unacceptable behavior include:

* The use of sexualized language or imagery, and sexual attention or
  advances of any kind
* Trolling, insulting or derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information, such as a physical or email
  address, without their explicit permission
* Other conduct which could reasonably be considered inappropriate in a
  professional setting

### Enforcement Responsibilities

Community leaders are responsible for clarifying and enforcing our standards of
acceptable behavior and will take appropriate and fair corrective action in
response to any behavior that they deem inappropriate, threatening, offensive,
or harmful.

Community leaders have the right and responsibility to remove, edit, or reject
comments, commits, code, wiki edits, issues, and other contributions that are
not aligned to this Code of Conduct, and will communicate reasons for moderation
decisions when appropriate.

### Scope

This Code of Conduct applies within all community spaces, and also applies when
an individual is officially representing the community in public spaces.
Examples of representing our community include using an official e-mail address,
posting via an official social media account, or acting as an appointed
representative at an online or offline event.

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported to the community leaders responsible for enforcement at
[INSERT CONTACT METHOD].
All complaints will be reviewed and investigated promptly and fairly.

All community leaders are obligated to respect the privacy and security of the
reporter of any incident.

### Enforcement Guidelines

Community leaders will follow these Community Impact Guidelines in determining
the consequences for any action they deem in violation of this Code of Conduct:

#### 1. Correction

**Community Impact**: Use of inappropriate language or other behavior deemed
unprofessional or unwelcome in the community.

**Consequence**: A private, written warning from community leaders, providing
clarity around the nature of the violation and an explanation of why the
behavior was inappropriate. A public apology may be requested.

#### 2. Warning

**Community Impact**: A violation through a single incident or series
of actions.

**Consequence**: A warning with consequences for continued behavior. No
interaction with the people involved, including unsolicited interaction with
those enforcing the Code of Conduct, for a specified period of time. This
includes avoiding interactions in community spaces as well as external channels
like social media. Violating these terms may lead to a temporary or
permanent ban.

#### 3. Temporary Ban

**Community Impact**: A serious violation of community standards, including
sustained inappropriate behavior.

**Consequence**: A temporary ban from any sort of interaction or public
communication with the community for a specified period of time. No public or
private interaction with the people involved, including unsolicited interaction
with those enforcing the Code of Conduct, is allowed during this period.
Violating these terms may lead to a permanent ban.

#### 4. Permanent Ban

**Community Impact**: Demonstrating a pattern of violation of community
standards, including sustained inappropriate behavior,  harassment of an
individual, or aggression toward or disparagement of classes of individuals.

**Consequence**: A permanent ban from any sort of public interaction within
the community.

### Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage],
version 2.0, available at
https://www.contributor-covenant.org/version/2/0/code_of_conduct.html.

Community Impact Guidelines were inspired by [Mozilla's code of conduct
enforcement ladder](https://github.com/mozilla/diversity).

[homepage]: https://www.contributor-covenant.org

For answers to common questions about this code of conduct, see the FAQ at
https://www.contributor-covenant.org/faq. Translations are available at
https://www.contributor-covenant.org/translations.
