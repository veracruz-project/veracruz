/*
 * Hex dump utilities
 *
 * ## Authors
 *
 * The Veracruz Development Team.
 *
 * ## Licensing and copyright notice
 *
 * See the `LICENSE.md` file in the Veracruz root directory for
 * information on licensing and copyright.
 *
 */

#ifndef XXD_H
#define XXD_H

#include <stdio.h>
#include <stdint.h>

// printfs a full xxd style hexdump
void xxd(const void *pbuf, size_t len);

// printfs the provided buffer as a hex string
//
// Note this does not output a trailing newline, allowing
// the output to be interleaved with other printf calls
void hex(const void *pbuf, size_t len);

#endif
