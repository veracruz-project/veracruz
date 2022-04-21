# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.

sel4_kernel_platform := lkvm

sel4_dts_path := $(sel4_src)/tools/dts/lkvm.dts

runtime_feature_flags := --features icecap-lkvm

.PHONY: clean-plat
clean-plat:

.PHONY: run
run:

.PHONY: debug
debug:
