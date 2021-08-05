/*
 * base64 utilities
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

#include "base64.h"
#include <kernel.h>
#include <string.h>

// convenience functions
static inline uint32_t base64_aligndown(uint32_t a, uint32_t alignment) {
    return a - (a % alignment);
}

static inline uint32_t base64_alignup(uint32_t a, uint32_t alignment) {
    return base64_aligndown(a + alignment-1, alignment);
}

// Find what the size would be after base64 encoding
size_t base64_encode_size(size_t in_len);

size_t base64_encode_size(size_t in_len) {
    return 4*(base64_alignup(in_len, 3) / 3);
}

// mapping from int to base64 character
static const char BASE64_ENCODE[] = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/");

// Encode base64
//
// Note that base64_encode encodes from back to front, allowing
// the in and out buffers to be set to the same buffer
//
// Returns the number of bytes written, or a negative error code
ssize_t base64_encode(
        const uint8_t *in, size_t in_len,
        char *out, size_t out_len);

ssize_t base64_encode(
        const uint8_t *in, size_t in_len,
        char *out, size_t out_len) {
    size_t e_len = base64_encode_size(in_len);
    if (e_len+1 > out_len) {
        return -EOVERFLOW;
    }
    out[e_len] = '\0';

    size_t rin_len = base64_alignup(in_len, 3);
    for (size_t i = 0, j = 0; i < in_len; i += 3, j += 4) {
        size_t v = in[rin_len-i-3];
        v = rin_len-i-3+1 < in_len ? (v << 8 | in[rin_len-i-3+1]) : (v << 8);
        v = rin_len-i-3+2 < in_len ? (v << 8 | in[rin_len-i-3+2]) : (v << 8);

        out[e_len-j-4]   = BASE64_ENCODE[(v >> 18) & 0x3f];
        out[e_len-j-4+1] = BASE64_ENCODE[(v >> 12) & 0x3f];

        if (rin_len-i-3+1 < in_len) {
            out[e_len-j-4+2] = BASE64_ENCODE[(v >> 6) & 0x3f];
        } else {
            out[e_len-j-4+2] = '=';
        }

        if (rin_len-i-3+2 < in_len) {
            out[e_len-j-4+3] = BASE64_ENCODE[v & 0x3f];
        } else {
            out[e_len-j-4+3] = '=';
        }
    }

    return e_len;
}

// custom strnlen, behaves the same as strnlen
//
// this is needed since strnlen is not available on all platforms
//
static size_t base64_strnlen(const char *s, size_t s_len) {
    for (size_t i = 0; i < s_len; i++) {
        if (s[i] == '\0') {
            return i;
        }
    }

    return s_len;
}

// Find what the size would be after base64 decoding
//
// Note that base64_decode_size needs the in buffer in order
// to check for padding symbols
size_t base64_decode_size(const char *in, size_t in_len) {
    size_t e_len = base64_strnlen(in, in_len);

    size_t x = 3*(e_len/4);
    for (size_t i = 0; i < e_len && in[e_len-i-1] == '='; i++) {
        x -= 1;
    }

    return x;
}

// mapping from base64 character - '+' (the first base64 character) to 
// its int value, with -1 indicating the given character is invalid
static const int8_t BASE64_DECODE[] = {
    62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1,
    -1, -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

// checks that a given character is valid base64 (including padding symbols)
static bool base64_isvalid(char c) {
    if (c >= '0' && c <= '9') {
        return true;
    } else if (c >= 'A' && c <= 'Z') {
        return true;
    } else if (c >= 'a' && c <= 'z') {
        return true;
    } else if (c == '+' || c == '/' || c == '=') {
        return true;
    } else {
        return false;
    }
}

// decode base64
//
// Note that base64_decode decodes from front to back, allowing
// the in and out buffers to be set to the same buffer
//
// Returns the number of bytes written, or a negative error code
ssize_t base64_decode(
        const char *in, size_t in_len,
        char *out, size_t out_len) {
    size_t e_len = base64_strnlen(in, in_len);
    if (e_len % 4 != 0) {
        return -EINVAL;
    }

    size_t d_len = base64_decode_size(in, in_len);
    if (d_len > out_len) {
        return -EOVERFLOW;
    }

    for (size_t i = 0; i < e_len; i++) {
        if (!base64_isvalid(in[i])) {
            return -EILSEQ;
        }
    }

    for (size_t i = 0, j = 0; i < e_len; i += 4, j += 3) {
        size_t v = BASE64_DECODE[in[i]-43];
        v = (v << 6) | BASE64_DECODE[in[i+1]-43];
        v = in[i+2] == '=' ? (v << 6) : ((v << 6) | BASE64_DECODE[in[i+2]-43]);
        v = in[i+3] == '=' ? (v << 6) : ((v << 6) | BASE64_DECODE[in[i+3]-43]);

        out[j] = (v >> 16) & 0xff;

        if (in[i+2] != '=') {
            out[j+1] = (v >> 8) & 0xff;
        }

        if (in[i+3] != '=') {
            out[j+2] = v & 0xff;
        }
    }

    return d_len;
}

