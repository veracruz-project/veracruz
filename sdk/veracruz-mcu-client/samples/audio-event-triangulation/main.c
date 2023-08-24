/*
 * Audio Event Triangulation demo for the Veracruz MCU Client
 *
 * This example application contains an audio sample of a "clap", an
 * audio event with an associated location and timestamp. It connects
 * to the configured Veracruz server in order to contribute its audio
 * recording to the confidential computation.
 *
 * With enough audio events (>3), the triangulated source of the audio
 * event can be calculated in the enclave, and retrieved without leaking
 * any of the sensitive data used in the computation, such as the audio
 * signal itself, or the device's locations.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kernel.h>

#include "xxd.h"
#include "vc.h"
#include "clap.h"
#include "policy.h"

// Render audio samples as ascii
void dump_samples(const int16_t *samples, size_t len,
        size_t width, size_t height) {
    int32_t global_min = 0;
    int32_t global_max = 0;
    for (size_t i = 0; i < len; i++) {
        if (samples[i] < global_min) {
            global_min = samples[i];
        }
        if (samples[i] > global_max) {
            global_max = samples[i];
        }
    }

    size_t slice = len / width;
    for (size_t y = 0; y < height/2; y++) {
        for (size_t x = 0; x < width; x++) {
            int32_t min = 0;
            int32_t max = 0;
            for (size_t i = 0; i < slice; i++) {
                if (samples[x*slice+i] < min) {
                    min = samples[x*slice+i];
                }
                if (samples[x*slice+i] > max) {
                    max = samples[x*slice+i];
                }
            }

            min = (height*(min-global_min)) / (global_max-global_min);
            max = (height*(max-global_min)) / (global_max-global_min);

            if (2*y >= min && 2*y <= max && 2*y+1 >= min && 2*y+1 <= max) {
                VC_LOG(":");
            } else if (2*y >= min && 2*y <= max) {
                VC_LOG("'");
            } else if (2*y+1 >= min && 2*y+1 <= max) {
                VC_LOG(".");
            } else {
                VC_LOG(" ");
            }
        }
        VC_LOG("\n");
    }
}

// Display GPS coordinates in a human readable form
void dump_gps(int32_t y, int32_t x) {
    int32_t absy = y >= 0 ? y : -y; 
    int32_t absx = x >= 0 ? x : -x; 
    VC_LOG("%d°%02d'%02d.%02d\"%c %d°%02d'%02d.%02d\"%c",
        absy / (1024*1024),
        (absy / (1024*1024/60)) % 60,
        (absy / (1024*1024/60/60)) % 60,
        (absy / (1024*1024/60/60/100)) % 100,
        y >= 0 ? 'N' : 'S',
        absx / (1024*1024),
        (absx / (1024*1024/60)) % 60,
        (absx / (1024*1024/60/60)) % 60,
        (absx / (1024*1024/60/60/100)) % 100,
        y >= 0 ? 'E' : 'W');
}


// Veracruz client
vc_t vc;

// entry point
void main(void) {
    VC_LOGLN("\033[0;32msystem started\033[m");
    VC_LOGLN("listening for audio...");
    k_sleep(Z_TIMEOUT_MS(DELAY*1000));

    // show audio event
    VC_LOGLN("\033[1;33mpeak detected, current window:\033[m");
    dump_samples(CLAP_SAMPLES, sizeof(CLAP_SAMPLES)/sizeof(int16_t), 76, 2*8);

    // other metadata
    VC_LOG("\033[1;33mlocation:\033[m ");
    dump_gps(CLAP_LOCATION_Y, CLAP_LOCATION_X);
    VC_LOGLN("");
    VC_LOGLN("\033[1;33mtimestamp:\033[m %u", CLAP_TIMESTAMP);
    k_sleep(Z_TIMEOUT_MS(DELAY*1000));

    // Connect to the Veracruz enclave and verify the enclave's hash
    int err = vc_connect(&vc);
    if (err) {
        VC_LOGLN("vc_connect failed (%d)", err);
        exit(1);
    }
    k_sleep(Z_TIMEOUT_MS(DELAY*1000));

    // package metadata + window
    uint8_t *data = malloc(3*4 + sizeof(CLAP_SAMPLES));
    data[ 0] = (uint8_t)(CLAP_TIMESTAMP >>  0);
    data[ 1] = (uint8_t)(CLAP_TIMESTAMP >>  8);
    data[ 2] = (uint8_t)(CLAP_TIMESTAMP >> 16);
    data[ 3] = (uint8_t)(CLAP_TIMESTAMP >> 24);
    data[ 4] = (uint8_t)((uint32_t)CLAP_LOCATION_Y >>  0);
    data[ 5] = (uint8_t)((uint32_t)CLAP_LOCATION_Y >>  8);
    data[ 6] = (uint8_t)((uint32_t)CLAP_LOCATION_Y >> 16);
    data[ 7] = (uint8_t)((uint32_t)CLAP_LOCATION_Y >> 24);
    data[ 8] = (uint8_t)((uint32_t)CLAP_LOCATION_X >>  0);
    data[ 9] = (uint8_t)((uint32_t)CLAP_LOCATION_X >>  8);
    data[10] = (uint8_t)((uint32_t)CLAP_LOCATION_X >> 16);
    data[11] = (uint8_t)((uint32_t)CLAP_LOCATION_X >> 24);
    for (int i = 0; i < sizeof(CLAP_SAMPLES)/sizeof(int16_t); i++) {
        data[12+i*2 + 0] = (uint8_t)((uint32_t)CLAP_SAMPLES[i] >> 0);
        data[12+i*2 + 1] = (uint8_t)((uint32_t)CLAP_SAMPLES[i] >> 8);
    }

    // send some data
    err = vc_send_data(&vc, CLAP_DATA_NAME, data, 3*4 + sizeof(CLAP_SAMPLES));
    if (err) {
        VC_LOGLN("vc_send_data failed (%d)", err);
        exit(1);
    }
    k_sleep(Z_TIMEOUT_MS(DELAY*1000));

    VC_LOGLN("disconnecting");
    err = vc_close(&vc);
    if (err) {
        VC_LOGLN("vc_close failed (%d)", err);
        exit(1);
    }

    VC_LOGLN("\033[32mdone!\033[m audio uploaded to enclave{%s:%d}",
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    exit(0);
}
