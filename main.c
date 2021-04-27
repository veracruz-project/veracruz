/*
 * mini-durango - A Veracruz client targetting microcontroller devices
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <kernel.h>

#include "xxd.h"
#include "vc.h"

// Veracruz client
vc_t vc;

// entry point
void main(void) {
    // Attest and connect to the Veracruz enclave
    int err = vc_attest_and_connect(&vc);
    if (err) {
        printf("vc_attest_and_connect failed (%d)\n", err);
        exit(1);
    }
    printf("connected!\n");

    // send some data
    err = vc_send_data(&vc, "input-0", "hello world!", sizeof("hello world!"));
    if (err) {
        printf("vc_send_data failed (%d)\n", err);
        exit(1);
    }
    printf("sent data!\n");

    err = vc_close(&vc);
    if (err) {
        printf("vc_close failed (%d)\n", err);
        exit(1);
    }
    printf("closed!\n");
    
    exit(0);
}
