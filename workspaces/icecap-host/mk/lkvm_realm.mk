# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.


host_feature_flags := --features icecap-lkvm_realm --target aarch64-unknown-linux-gnu

COMPILERS = CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
	    RUSTFLAGS="-C linker=aarch64-linux-gnu-gcc -C target-feature=+crt-static"

.PHONY: rustup-plat
rustup-plat:
	rustup target add aarch64-unknown-linux-gnu
