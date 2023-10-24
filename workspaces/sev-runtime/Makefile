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

.PHONY: all clean clean-cargo-lock doc fmt clippy

default: all

WORKSPACE_DIR = $(abspath ..)

include $(WORKSPACE_DIR)/common.mk

unresolved_crates_path := $(shell pwd)/crates

all: initramfs_sev

initramfs_sev: ./target/x86_64-unknown-linux-musl/debug/sev-runtime-manager linux-kernel
	cp ./target/x86_64-unknown-linux-musl/debug/sev-runtime-manager ./init
	echo -n init | cpio --null --create -V --format=newc -O ./initramfs_sev

./target/x86_64-unknown-linux-musl/debug/sev-runtime-manager: FORCE
	RUSTFLAGS="--remap-path-prefix $(unresolved_crates_path)=$(shell readlink -f $(unresolved_crates_path))" \
	cargo build --target x86_64-unknown-linux-musl $(PROFILE_FLAG) $(V_FLAG)
FORCE:

.PHONY:
linux-kernel: FORCE
    git clone https://github.com/AMDESE/linux.git
	cp guest_config linux/.config
	cd linux; \
		git checkout 6e7765cb477a9753670d4351d14de93f1e9dbbd4; \
		make

OVMF: FORCE
	git clone --branch snp-latest --depth 1 https://github.com/AMDESE/AMDSEV.git
	cd AMDSEV; ./build.sh --package ovmf


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
