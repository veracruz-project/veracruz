# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
# and copyright information.

ICECAP_PLAT ?= virt

build_dir := build
target_dir := $(build_dir)/target
bin_dir := $(build_dir)/bin

kebab_to_caml = $(subst -,_,$(1))
capitalize = $(shell echo $(1) | tr '[:lower:]' '[:upper:]')
cargo_target_config_prefix = CARGO_TARGET_$(call capitalize,$(call kebab_to_caml,$(1)))_

rust_target_build = $(shell uname -m)-unknown-linux-gnu

.PHONY: none
none:

$(build_dir) $(bin_dir):
	mkdir $@
