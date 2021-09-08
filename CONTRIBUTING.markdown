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
Please see the `LICENSE_MIT.markdown` file in the Veracruz repository for the
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
   Makefile.  A Git pre-commit hook is available in the `githooks`
   directory can be used to automatically check Rust files are formatted
   correctly before they are committed.  To enable this hook, run the
   `make setup-githooks` command which will automatically install
   `rustfmt`, if needed, and set the Git hooks directory to `githooks`.
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
the full text of which is available in the CODE_OF_CONDUCT Markdown file
available in the Veracruz root directory, or through the Github web
interface.
