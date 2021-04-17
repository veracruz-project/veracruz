/*
 * Hex dump utilities
 *
 */

#include "xxd.h"

// hexdump
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

        for (int j = 0; j < 16 && i+j < len; j++) {
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

// bytes to hex, no newline at the end
void hex(const void *pbuf, size_t len) {
    const uint8_t *buf = pbuf;
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

