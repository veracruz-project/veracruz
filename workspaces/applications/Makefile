# Applications Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSE.md` file in the Veracruz root directory for
# licensing and copyright information.

.PHONY: all clean clean-cargo-lock doc fmt

WORKSPACE_DIR = $(abspath ..)
include $(WORKSPACE_DIR)/common.mk

all:
	cargo build $(PROFILE_FLAG) $(V_FLAG)

doc:
	cargo doc

fmt:
	cargo fmt

clean:
	cargo clean

clean-cargo-lock:
	rm -f Cargo.lock
