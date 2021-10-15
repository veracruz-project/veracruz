/*
 * AUTHORS
 *
 * The Veracruz Development Team.
 *
 * COPYRIGHT
 *
 * See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
 * and copyright information.
 *
 */

#pragma once

#include <stddef.h>
#include <icecap_utils.h>

#define printf icecap_utils_debug_printf

int snprintf(char *str, size_t size, const char *format, ...);
