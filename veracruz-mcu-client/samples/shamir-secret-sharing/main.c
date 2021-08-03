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
    VC_LOGLN("system started");
    int err;

    // upload shares
    for (int i = 0; i < sizeof(SHARES)/sizeof(SHARES[0]); i++) {
        VC_LOGLN("uploading share %d to %s...", i+1, SHARES[i].name);
        err = vc_connect(&vc);
        VC_LOGLN("vc_connect -> %d", err);
        if (err) {
            exit(1);
        }

        err = vc_send_data(&vc, SHARES[i].name, SHARES[i].data, SHARES[i].size);
        VC_LOGLN("vc_send_data -> %d", err);
        if (err) {
            exit(1);
        }

        err = vc_close(&vc);
        VC_LOGLN("vc_close -> %d", err);
        if (err) {
            exit(1);
        }
    }

    // upload the binary
    VC_LOGLN("uploading binary test-binary.wasm...");
    err = vc_connect(&vc);
    VC_LOGLN("vc_connect -> %d", err);
    if (err) {
        exit(1);
    }

    err = vc_send_program(&vc, "test-binary.wasm", BINARY, sizeof(BINARY));
    VC_LOGLN("vc_send_program -> %d", err);
    if (err) {
        exit(1);
    }

    err = vc_close(&vc);
    VC_LOGLN("vc_close -> %d", err);
    if (err) {
        exit(1);
    }

    // download the result
    VC_LOGLN("downloading result test-binary.wasm...");
    err = vc_connect(&vc);
    VC_LOGLN("vc_connect -> %d", err);
    if (err) {
        exit(1);
    }

    uint8_t result[256];
    memset(result, 0xcc, sizeof(result));
    ssize_t result_len = vc_request_result(&vc, "test-binary.wasm", result, sizeof(result));
    VC_LOGLN("vc_request_result -> %d", err);
    if (result_len < 0) {
        exit(1);
    }

    err = vc_close(&vc);
    VC_LOGLN("vc_close -> %d", err);
    if (err) {
        exit(1);
    }

    // initiate shutdown
    VC_LOGLN("shutting down server...");
    err = vc_connect(&vc);
    VC_LOGLN("vc_connect -> %d", err);
    if (err) {
        exit(1);
    }

    err = vc_request_shutdown(&vc);
    VC_LOGLN("vc_request_shutdown -> %d", err);
    if (err) {
        exit(1);
    }

    err = vc_close(&vc);
    VC_LOGLN("vc_close -> %d", err);
    if (err) {
        exit(1);
    }

    // check results are correct?
    VC_LOG("computed: ");
    for (int i = 0; i < result_len; i++) {
        if (result[i] >= ' ' && result[i] <= '~') {
            VC_LOG("%c", result[i]);
        } else {
            VC_LOG("\\x%02x", result[i]);
        }
    }
    VC_LOG("\n");
    VC_LOG("expected: ");
    for (int i = 0; i < result_len; i++) {
        if (RESULT[i] >= ' ' && RESULT[i] <= '~') {
            VC_LOG("%c", RESULT[i]);
        } else {
            VC_LOG("\\x%02x", RESULT[i]);
        }
    }
    VC_LOG("\n");

    if (result_len != sizeof(RESULT)
            || memcmp(result, RESULT, result_len) != 0) {
        VC_LOGLN("does not match \"%s\"", RESULT);
        exit(2);
    }

    VC_LOGLN("done!");
    exit(0);
}
