/*
 * base64 utilities
 *
 * ## Authors
 * 
 * The Veracruz Development Team.
 *
 * ## Licensing and copyright notice
 *
 * See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
 * information on licensing and copyright.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef BASE64_H
#define BASE64_H

// Find what the size would be after base64 encoding
size_t base64_encode_size(size_t in_len);

// Encode base64
//
// Note that base64_encode encodes from back to front, allowing
// the in and out buffers to be set to the same buffer
//
// Returns the number of bytes written, or a negative error code
ssize_t base64_encode(
        const uint8_t *in, size_t in_len,
        char *out, size_t out_len);

// Find what the size would be after base64 decoding
//
// Note that base64_decode_size needs the in buffer in order
// to check for padding symbols
size_t base64_decode_size(const char *in, size_t in_len);

// decode base64
//
// Note that base64_decode decodes from front to back, allowing
// the in and out buffers to be set to the same buffer
//
// Returns the number of bytes written, or a negative error code
ssize_t base64_decode(
        const char *in, size_t in_len,
        char *out, size_t out_len);

#endif
