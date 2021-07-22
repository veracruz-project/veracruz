/*
 * Hex dump utilities
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
