/*
 * AUTHORS
 *
 * The Veracruz Development Team.
 *
 * COPYRIGHT
 *
 * See the `LICENSE_MIT.markdown` file in the Veracruz root directory
 * for licensing and copyright information.
 *
 */

#pragma once

#include <stddef.h>
#include <sys/types.h>

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
