/*
 * mini-durango - A Veracruz client targetting microcontroller devices
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <kernel.h>

#include "xxd.h"
#include "qemu.h"
#include "vc.h"

// Veracruz client
vc_t vc;

// entry point
void main(void) {
    // Attest and connect to the Veracruz enclave
    int err = vc_attest_and_connect(&vc);
    if (err) {
        printf("vc_attest_and_connect failed (%d)\n", err);
        qemu_exit();
    }
    printf("connected!\n");

    err = vc_close(&vc);
    if (err) {
        printf("vc_close failed (%d)\n", err);
        qemu_exit();
    }
    printf("closed!\n");
    
    qemu_exit();
}
