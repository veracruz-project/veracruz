/*
 * mini-durango - A Veracruz client targetting microcontroller devices
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <random/rand32.h>
#include <kernel.h>

#include "nanopb/pb.h"
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "transport_protocol.pb.h"

#include "policy.h"
#include "xxd.h"
#include "base64.h"
#include "http.h"
#include "qemu.h"
#include "vc.h"


//// application logic ////
void main(void) {
    // attest the Veracruz enclave
    int err = vc_attest();
    if (err) {
        printf("vc_attest failed (%d)\n", err);
        qemu_exit();
    }

    printf("success!\n");
    qemu_exit();
}
