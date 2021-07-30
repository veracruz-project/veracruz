/*
 * A Veracruz client targetting microcontroller devices
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kernel.h>

#include "xxd.h"
#include "vc.h"
#include "binary.h"
#include "policy.h"

// Some test data
const uint8_t SHARE1[] = {
    0x01, 0xdc, 0x06, 0x1a, 0x7b, 0xda, 0xf7, 0x76,
    0x16, 0xdd, 0x59, 0x15, 0xf3, 0xb4,
};

const uint8_t SHARE2[] = {
    0x02, 0x7f, 0x38, 0xe2, 0x7b, 0x5a, 0x02, 0xa2,
    0x88, 0xd0, 0x64, 0x96, 0x53, 0x64
};

const uint8_t SHARE3[] = {
    0x03, 0xeb, 0x5b, 0x94, 0x6c, 0xef, 0xd5, 0x83,
    0xf1, 0x7f, 0x51, 0xe7, 0x81, 0xda
};

const char RESULT[13] = {"Hello World!\n"};

const struct {
    const char *name;
    const uint8_t *data;
    size_t size;
} SHARES[] = {
    {"input-0", SHARE1, sizeof(SHARE1)},
    {"input-1", SHARE2, sizeof(SHARE2)},
    {"input-2", SHARE3, sizeof(SHARE3)},
};

// Veracruz client
vc_t vc;

// entry point
void main(void) {
    printf("system started\n");
    int err;

    // upload shares
    for (int i = 0; i < sizeof(SHARES)/sizeof(SHARES[0]); i++) {
        printf("uploading share %d to %s...\n", i+1, SHARES[i].name);
        err = vc_connect(&vc);
        printf("vc_connect -> %d\n", err);
        if (err) {
            exit(1);
        }

        err = vc_send_data(&vc, SHARES[i].name, SHARES[i].data, SHARES[i].size);
        printf("vc_send_data -> %d\n", err);
        if (err) {
            exit(1);
        }

        err = vc_close(&vc);
        printf("vc_close -> %d\n", err);
        if (err) {
            exit(1);
        }
    }

    // upload the binary
    printf("uploading binary test-binary.wasm...\n");
    err = vc_connect(&vc);
    printf("vc_connect -> %d\n", err);
    if (err) {
        exit(1);
    }

    err = vc_send_program(&vc, "test-binary.wasm", BINARY, sizeof(BINARY));
    printf("vc_send_program -> %d\n", err);
    if (err) {
        exit(1);
    }

    err = vc_close(&vc);
    printf("vc_close -> %d\n", err);
    if (err) {
        exit(1);
    }

    // download the result
    printf("downloading result test-binary.wasm...\n");
    err = vc_connect(&vc);
    printf("vc_connect -> %d\n", err);
    if (err) {
        exit(1);
    }

    uint8_t result[256];
    memset(result, 0xcc, sizeof(result));
    ssize_t result_len = vc_request_result(&vc, "test-binary.wasm", result, sizeof(result));
    printf("vc_request_result -> %d\n", err);
    if (result_len < 0) {
        exit(1);
    }

    err = vc_close(&vc);
    printf("vc_close -> %d\n", err);
    if (err) {
        exit(1);
    }

    // initiate shutdown
    printf("shutting down server...\n");
    err = vc_connect(&vc);
    printf("vc_connect -> %d\n", err);
    if (err) {
        exit(1);
    }

    err = vc_request_shutdown(&vc);
    printf("vc_request_shutdown -> %d\n", err);
    if (err) {
        exit(1);
    }

    err = vc_close(&vc);
    printf("vc_close -> %d\n", err);
    if (err) {
        exit(1);
    }

    // check results are correct?
    printf("computed: ");
    for (int i = 0; i < result_len; i++) {
        if (result[i] >= ' ' && result[i] <= '~') {
            printf("%c", result[i]);
        } else {
            printf("\\x%02x", result[i]);
        }
    }
    printf("\n");
    printf("expected: ");
    for (int i = 0; i < result_len; i++) {
        if (RESULT[i] >= ' ' && RESULT[i] <= '~') {
            printf("%c", RESULT[i]);
        } else {
            printf("\\x%02x", RESULT[i]);
        }
    }
    printf("\n");

    if (result_len != sizeof(RESULT)
            || memcmp(result, RESULT, result_len) != 0) {
        printf("does not match \"%s\"", RESULT);
        exit(2);
    }

    printf("done!\n");
    exit(0);
}
