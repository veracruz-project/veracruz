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
V ?= 0

export PROFILE V

ifeq ($(PROFILE),dev)
    PROFILE_PATH = debug
    PROFILE_FLAG =
endif

ifeq ($(V), 0)
    V_FLAG =
    Q = @
else
    V_FLAG = -v
    Q =
endif
