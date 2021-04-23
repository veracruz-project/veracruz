/*
 * Veracruz client aimed at microcontrollers, built in Zephyr OS
 *
 */

#include "vc.h"

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


int vc_attest(void) {
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
        return request_len;
    }

    printf("request:\n");
    xxd(request_buf, request_len);

    // POST challenge
    printf("connecting to %s:%d...\n",
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT);
    uint8_t pat_buf[1024];
    ssize_t pat_len = http_post(
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT,
            "/sinaloa",
            request_buf,
            request_len,
            pat_buf,
            sizeof(pat_buf));
    if (pat_len < 0) {
        printf("http_post failed (%d)\n", pat_len);
        return pat_len;
    }

    printf("http_post -> %d\n", pat_len);
    printf("attest: challenge response:\n");
    xxd(pat_buf, pat_len);

    // forward to proxy attestation server
    printf("connecting to %s:%d...\n",
            PROXY_ATTESTATION_SERVER_HOST,
            PROXY_ATTESTATION_SERVER_PORT);
    uint8_t response_buf[256];
    ssize_t response_len = http_post(
            PROXY_ATTESTATION_SERVER_HOST,
            PROXY_ATTESTATION_SERVER_PORT,
            "/VerifyPAT",
            pat_buf,
            pat_len,
            response_buf,
            sizeof(response_buf));
    if (response_len < 0) {
        printf("http_post failed (%d)\n", response_len);
        return response_len;
    }

    printf("http_post -> %d\n", response_len);
    printf("attest: PAT response:\n");
    xxd(response_buf, response_len);

    // decode base64
    ssize_t verif_len = base64_decode(
            response_buf, sizeof(response_buf),
            response_buf, sizeof(response_buf));
    if (verif_len < 0) {
        printf("base64_decode failed (%d)\n", verif_len);
        return verif_len;
    }
    
    printf("attest: PAT decoded response:\n");
    xxd(response_buf, verif_len);

    if (verif_len < 131) {
        printf("pat response too small\n");
        return -EOVERFLOW;
    }

    // check that challenge matches
    if (memcmp(challenge, &response_buf[8], 32) != 0) {
        printf("challenge mismatch\n");
        printf("expected: ");
        for (int i = 0; i < sizeof(challenge); i++) {
            printf("%02x", challenge[i]);
        }
        printf("\n");
        printf("recieved: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", response_buf[8+i]);
        }
        printf("\n");
        return -EBADE;
    }

    // check that enclave hash matches policy
    if (memcmp(&response_buf[47], RUNTIME_MANAGER_HASH,
            sizeof(RUNTIME_MANAGER_HASH)) != 0) {
        printf("enclave hash mismatch\n");
        printf("expected: ");
        for (int i = 0; i < sizeof(RUNTIME_MANAGER_HASH); i++) {
            printf("%02x", RUNTIME_MANAGER_HASH[i]);
        }
        printf("\n");
        printf("recieved: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", response_buf[8+i]);
        }
        printf("\n");
        return -EBADE;
    }

    // recieved values
    printf("enclave name: %.*s\n", 7, &response_buf[124]);
    printf("enclave hash: ");
    hex(&response_buf[47], 32);
    printf("\n");
    printf("enclave cert hash: ");
    hex(&response_buf[86], 32);
    printf("\n");

    return 0;
}
