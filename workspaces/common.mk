# common.mk
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT AND LICENSING
#
# See the `LICENSING.markdown` file in the Veracruz root directory for
# licensing and copyright information.

PROFILE ?= release
PROFILE_PATH = release
PROFILE_FLAG = --release

export PROFILE

ifeq ($(PROFILE),dev)
    PROFILE_PATH = debug
    PROFILE_FLAG =
endif
