/*
 * Hex dump utilities
 *
 * ## Authors
 *
 * The Veracruz Development Team.
 *
 * ## Licensing and copyright notice
 *
 * See the `LICENSE.markdown` file in the Veracruz root directory for
 * information on licensing and copyright.
 *
 */

#ifndef XXD_H
#define XXD_H

#include <stdio.h>
#include <stdint.h>

// hexdump
void xxd(const void *pbuf, size_t len);

// bytes to hex, no newline at the end
void hex(const void *pbuf, size_t len);

#endif
