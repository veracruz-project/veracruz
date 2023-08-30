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

#include "xxd.h"

// printfs a full xxd style hexdump
void xxd(const void *pbuf, size_t len) {
    const uint8_t *buf = pbuf;

    for (int i = 0; i < len; i += 16) {
        printf("%08x: ", i);

        for (int j = 0; j < 16; j++) {
            if (i+j < len) {
                printf("%02x ", buf[i+j]);
            } else {
                printf("   ");
            }
        }

        printf(" ");

        for (int j = 0; j < 16; j++) {
            if (i+j < len) {
                if (buf[i+j] >= ' ' && buf[i+j] <= '~') {
                    printf("%c", buf[i+j]);
                } else {
                    printf(".");
                }
            } else {
                printf(" ");
            }
        }

        printf("\n");
    }
}

// printfs the provided buffer as a hex string
//
// Note this does not output a trailing newline, allowing
// the output to be interleaved with other printf calls
void hex(const void *pbuf, size_t len) {
    const uint8_t *buf = pbuf;
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

