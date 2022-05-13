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

PROFILE ?= dev
PROFILE_PATH = debug
PROFILE_FLAG =
V ?= 0
BIN_DIR ?= /usr/local/bin

export PROFILE V BIN_DIR

ifeq ($(PROFILE),release)
    PROFILE_PATH = release
    PROFILE_FLAG = --release
endif

ifeq ($(V), 0)
    V_FLAG =
    Q = @
else
    V_FLAG = -v
    Q =
endif
