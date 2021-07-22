/*
 * base64 utilities
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef BASE64_H
#define BASE64_H

// compute size after encoding
size_t base64_encode_size(size_t in_len);

// encode base64
ssize_t base64_encode(
        const uint8_t *in, size_t in_len,
        char *out, size_t out_len);

// compute size after decoding
size_t base64_decode_size(const char *in, size_t in_len);

// decode base64
ssize_t base64_decode(
        const char *in, size_t in_len,
        char *out, size_t out_len);

#endif
