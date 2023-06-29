# Makefile
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root director for licensing
# and copyright information.

.PHONY: all clean clean-cargo-lock doc fmt clippy sev-runtime-manager

default: all

WORKSPACE_DIR = $(abspath ..)

include $(WORKSPACE_DIR)/common.mk

unresolved_crates_path := $(shell pwd)/crates

all: .guest_image_canary

.guest_image_canary: ./target/x86_64-unknown-linux-musl/debug/sev-runtime-manager
	virt-sysprep -a sev-guest-runtime-manager.img \
		-copy-in "./target/x86_64-unknown-linux-musl/debug/sev-runtime-manager:/root/" \
		-copy-in veracruz.service:/etc/systemd/system/ \
		-copy-in "./modules:/etc/" \
		--link /etc/systemd/system/veracruz.service:/etc/systemd/system/multi-user.target.wants/veracruz.service
	touch .guest_imag3e_canary

./target/x86_64-unknown-linux-musl/debug/sev-runtime-manager: FORCE
	RUSTFLAGS="--remap-path-prefix $(unresolved_crates_path)=$(shell readlink -f $(unresolved_crates_path))" \
	cargo build $(PROFILE_FLAG) $(V_FLAG)

FORCE:

doc:
	cargo doc

clippy:
	cargo clippy $(PROFILE_FLAG) $(V_FLAG) \
		-p sev-runtime-manager -p execution-engine \
		-p session-manager -p policy-utils -p platform-services
		-- --no-deps

fmt:
	cargo fmt

clean:
	@cargo clean

clean-cargo-lock:
	rm -f Cargo.lock
