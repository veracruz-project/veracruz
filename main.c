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


//// application logic ////

uint8_t buffer[10*1024];
uint8_t buffer2[10*1024];

void main(void) {
    // get random challenge
    // TODO Zephyr notes this is not cryptographically secure, is that an
    // issue? This will be an area to explore
    uint8_t challenge[32];
    sys_rand_get(challenge, sizeof(challenge));

    // TODO log? can we incrementally log?
    printf("attest: challenge: ");
    hex(challenge, sizeof(challenge));
    printf("\n");

    // construct attestation token request
    Tp_RuntimeManagerRequest request = {
        .which_message_oneof = Tp_RuntimeManagerRequest_request_proxy_psa_attestation_token_tag
    };
    memcpy(request.message_oneof.request_proxy_psa_attestation_token.challenge,
            challenge, sizeof(challenge));

    // encode
    // TODO this could be smaller, but instead could we tie protobuf encoding
    // directly into our GET function?
    uint8_t request_buf[256];
    pb_ostream_t request_stream = pb_ostream_from_buffer(
            request_buf, sizeof(request_buf));
    pb_encode(&request_stream, &Tp_RuntimeManagerRequest_msg, &request);

    // convert base64
    ssize_t request_len = base64_encode(
            request_buf, request_stream.bytes_written, 
            request_buf, sizeof(request_buf));
    if (request_len < 0) {
        printf("base64_encode failed (%d)\n", request_len);
        qemu_exit();
    }

    printf("request:\n");
    xxd(request_buf, request_len);

    // POST challenge
    printf("connecting to %s:%d...\n",
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT);
    ssize_t pat_len = http_post(
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT,
            "/sinaloa",
            request_buf,
            request_len,
            buffer,
            sizeof(buffer));
    if (pat_len < 0) {
        printf("http_post failed (%d)\n", pat_len);
        qemu_exit();
    }

    printf("http_post -> %d\n", pat_len);
    printf("attest: challenge response:\n");
    xxd(buffer, pat_len);

    // forward to proxy attestation server
    printf("connecting to %s:%d...\n",
            PROXY_ATTESTATION_SERVER_HOST,
            PROXY_ATTESTATION_SERVER_PORT);
    ssize_t res = http_post(
            PROXY_ATTESTATION_SERVER_HOST,
            PROXY_ATTESTATION_SERVER_PORT,
            "/VerifyPAT",
            buffer,
            pat_len,
            buffer,
            sizeof(buffer));
    if (res < 0) {
        printf("http_post failed (%d)\n", res);
        qemu_exit();
    }

    printf("http_post -> %d\n", res);
    printf("attest: PAT response:\n");
    xxd(buffer, res);

    // decode base64
    ssize_t verif_len = base64_decode(buffer, sizeof(buffer), buffer, sizeof(buffer));
    if (verif_len < 0) {
        printf("base64_decode failed (%d)\n", verif_len);
        qemu_exit();
    }
    
    printf("attest: PAT decoded response:\n");
    xxd(buffer, verif_len);

    if (verif_len < 131) {
        printf("pat response too small\n");
        qemu_exit();
    }

    // check that challenge matches
    if (memcmp(challenge, &buffer[8], 32) != 0) {
        printf("challenge mismatch\n");
        printf("expected: ");
        for (int i = 0; i < sizeof(challenge); i++) {
            printf("%02x", challenge[i]);
        }
        printf("\n");
        printf("recieved: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", buffer[8+i]);
        }
        printf("\n");
        qemu_exit();
    }

    // check that enclave hash matches policy
    if (memcmp(&buffer[47], RUNTIME_MANAGER_HASH, sizeof(RUNTIME_MANAGER_HASH)) != 0) {
        printf("enclave hash mismatch\n");
        printf("expected: ");
        for (int i = 0; i < sizeof(RUNTIME_MANAGER_HASH); i++) {
            printf("%02x", RUNTIME_MANAGER_HASH[i]);
        }
        printf("\n");
        printf("recieved: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", buffer[8+i]);
        }
        printf("\n");
        qemu_exit();
    }

    // recieved values
    printf("enclave name: %.*s\n", 7, &buffer[124]);
    printf("enclave hash: ");
    hex(&buffer[47], 32);
    printf("\n");
    printf("enclave cert hash: ");
    hex(&buffer[86], 32);
    printf("\n");

    qemu_exit();
}
