/*
 * Veracruz client aimed at microcontrollers, built in Zephyr OS
 *
 */

#include "vc.h"

#include <random/rand32.h>
#include <kernel.h>

#include <mbedtls/ssl.h>
#include <mbedtls/debug.h>

#include "nanopb/pb.h"
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "transport_protocol.pb.h"

#include "policy.h"
#include "xxd.h"
#include "base64.h"
#include "http.h"
#include "qemu.h"


//// attestation ////
int vc_attest(
        char *enclave_name, size_t enclave_name_len,
        uint8_t *enclave_cert_hash, size_t *enclave_cert_hash_len) {
    // check buffer sizes here, with the current Veracruz implementation
    // these are fixed sizes
    if (enclave_name_len < 7+1 || *enclave_cert_hash_len < 32) {
        return -EINVAL;
    }

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
    // TODO why verify_iat response not a protobuf?
    memcpy(enclave_name, &response_buf[124], 7);
    enclave_name[7] = '\0';
    memcpy(enclave_cert_hash, &response_buf[86], 32);
    *enclave_cert_hash_len = 32;

    printf("enclave name: %s\n", enclave_name);
    printf("enclave hash: ");
    hex(&response_buf[47], 32);
    printf("\n");
    printf("enclave cert hash: ");
    hex(enclave_cert_hash, *enclave_cert_hash_len);
    printf("\n");

    return 0;
}


//// Veracruz session handling ////
static void mbedtls_debug(void *ctx, int level,
        const char *file, int line,
        const char *str) {
    const char *basename = file;
    for (int i = 0; file[i]; i++) {
        if (file[i] == '/') {
            basename = &file[i+1];
        }
    }

    printf("%s:%d %s", basename, line, str);
}

static int vc_rawrng(void *p,
        uint8_t *buf, size_t len) {
    // TODO use cryptographically secure rng?
    sys_rand_get(buf, len);
    return 0;
}

static ssize_t vc_rawsend(void *p,
        const uint8_t *buf, size_t len) {
    vc_t *vc = p;

    if (vc->recv_len != 0) {
        printf("data left!?!?!?!? %d\n", vc->recv_len);
    }

    // encode with base64 + id (0)
    ssize_t data_len = 0;
    ssize_t res = snprintf(vc->send_buf, VC_SEND_BUFFER_SIZE,
            "%d ", vc->session_id);
    if (res < 0) {
        printf("formatting failed (%d)\n", res);
        return res;
    }
    data_len += res;
    res = base64_encode(
        buf, len,
        &vc->send_buf[data_len], VC_SEND_BUFFER_SIZE-data_len);
    if (res < 0) {
        printf("base64_encode failed (%d)\n", res);
        return res;
    }
    data_len += res;

    // send data over HTTP POST
    printf("sending to %s:%d:\n",
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT);
    xxd(vc->send_buf, data_len);
    ssize_t recv_len = http_post(
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT,
            "/mexico_city",
            vc->send_buf,
            data_len,
            vc->recv_buf,
            VC_RECV_BUFFER_SIZE);
    if (recv_len < 0) {
        printf("http_post failed (%d)\n", recv_len);
        return recv_len;
    }

    printf("http_post -> %d\n", recv_len);

    if (recv_len == 0) {
        // done, recieved nothing
        return len;
    }

    printf("ssl session: recv:\n");
    xxd(vc->recv_buf, recv_len);

    // we have a bit of parsing to do, first decode session id
    const uint8_t *parsing = vc->recv_buf;
    vc->session_id = strtol(parsing, (char **)&parsing, 10);
    if (parsing == vc->recv_buf) {
        printf("failed to parse session id\n");
        return -EILSEQ;
    }
    // skip space
    parsing += 1;
    printf("session id: %d\n", vc->session_id);

    // parse out base64 blobs, shuffling to front of our buffer
    uint8_t *parsed = vc->recv_buf;
    while (parsing < &vc->recv_buf[recv_len]) {
        int i = 0;
        while (parsing[i] && parsing[i] != ' ') {
            i += 1;
        }

        res = base64_decode(
                parsing, i,
                parsed, &vc->recv_buf[recv_len]-parsed);
        if (res < 0) {
            printf("base64_decode failed (%d)\n", res);
            return res;
        }

        parsing += i;
        parsed += res;

        // skip space
        if (parsing[0] == ' ') {
            parsing += 1;
        }
    }

    vc->recv_pos = vc->recv_buf;
    vc->recv_len = parsed - vc->recv_buf;

    printf("ssl session: parsed:\n");
    xxd(vc->recv_pos, vc->recv_len);

    // done!
    return len;
}

static ssize_t vc_rawrecv(void *p,
        uint8_t *buf, size_t len,
        uint32_t timeout) {
    vc_t *vc = p;

    if (vc->recv_len == 0) {
        // no data available? since we communicate over POSTs,
        // we'll never have data available
        printf("recv timeout\n");
        return MBEDTLS_ERR_SSL_TIMEOUT;
    }

    size_t diff = (len < vc->recv_len) ? len : vc->recv_len;
    memcpy(buf, vc->recv_pos, diff);
    vc->recv_pos += diff;
    vc->recv_len -= diff;
    return diff;
}

int vc_connect(vc_t *vc,
        // TODO need enclave name?
        const char *enclave_name,
        const uint8_t *enclave_cert_hash, size_t enclave_cert_hash_len) {
    // some setup
    vc->session_id = 0;
    vc->recv_len = 0;

    // check that requested ciphersuite is available, this can fail if
    // the ciphersuite isn't enabled in mbedtls's configuration
    if (mbedtls_ssl_ciphersuite_from_id(CIPHERSUITE) == NULL) {
        printf("required ciphersuite unavailable, "
                "is mbedtls configured correctly?\n");
        return -ENOSYS;
    }

    // allocate buffers
    vc->send_buf = malloc(VC_SEND_BUFFER_SIZE);
    if (!vc->send_buf) {
        return -ENOMEM;
    }

    vc->recv_buf = malloc(VC_RECV_BUFFER_SIZE);
    if (!vc->recv_buf) {
        free(vc->send_buf);
        return -ENOMEM;
    }

    // parse client cert/key
    mbedtls_x509_crt_init(&vc->client_cert);
    int err = mbedtls_x509_crt_parse_der(&vc->client_cert,
            CLIENT_CERT_DER, sizeof(CLIENT_CERT_DER));
    if (err) {
        printf("failed to parse client cert (%d)\n", err);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    mbedtls_pk_init(&vc->client_key);
    err = mbedtls_pk_parse_key(&vc->client_key,
            CLIENT_KEY_DER, sizeof(CLIENT_KEY_DER),
            NULL, 0);
    if (err) {
        printf("failed to parse client key (%d)\n", err);
        mbedtls_x509_crt_free(&vc->client_cert);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    // setup SSL connection
    mbedtls_ssl_init(&vc->session);
    mbedtls_ssl_config_init(&vc->session_cfg);

    err = mbedtls_ssl_config_defaults(&vc->session_cfg,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT);
    if (err) {
        printf("failed to configure SSL (%d)\n", err);
        mbedtls_ssl_config_free(&vc->session_cfg);
        mbedtls_pk_free(&vc->client_key);
        mbedtls_x509_crt_free(&vc->client_cert);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    // TODO fix this, is as is just for testing
    mbedtls_ssl_conf_authmode(&vc->session_cfg, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng(&vc->session_cfg, vc_rawrng, NULL);

    mbedtls_ssl_conf_ciphersuites(&vc->session_cfg, CIPHERSUITES);

    err = mbedtls_ssl_conf_own_cert(&vc->session_cfg,
            &vc->client_cert, &vc->client_key);
    if (err) {
        printf("failed to setup SSL session (%d)\n", err);
        mbedtls_ssl_config_free(&vc->session_cfg);
        mbedtls_pk_free(&vc->client_key);
        mbedtls_x509_crt_free(&vc->client_cert);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    // TODO remove debugging? hide behind logging?
    mbedtls_debug_set_threshold(4);
    mbedtls_ssl_conf_dbg(&vc->session_cfg, mbedtls_debug, vc);

    err = mbedtls_ssl_setup(&vc->session, &vc->session_cfg);
    if (err) {
        printf("failed to setup SSL session (%d)\n", err);
        mbedtls_ssl_config_free(&vc->session_cfg);
        mbedtls_pk_free(&vc->client_key);
        mbedtls_x509_crt_free(&vc->client_cert);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    // setup blocking IO functions
    mbedtls_ssl_set_bio(&vc->session,
            vc,
            vc_rawsend,
            NULL, // no non-blocking recv
            vc_rawrecv);

    // perform SSL handshake
    err = mbedtls_ssl_handshake(&vc->session);
    if (err) {
        printf("SSL handshake failed (%d)\n", err);
        mbedtls_ssl_free(&vc->session);
        mbedtls_ssl_config_free(&vc->session_cfg);
        mbedtls_pk_free(&vc->client_key);
        mbedtls_x509_crt_free(&vc->client_cert);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    return 0;
}

int vc_close(vc_t *vc) {
    mbedtls_ssl_free(&vc->session);
    mbedtls_ssl_config_free(&vc->session_cfg);
    mbedtls_pk_free(&vc->client_key);
    mbedtls_x509_crt_free(&vc->client_cert);
    free(vc->recv_buf);
    free(vc->send_buf);
    return 0;
}

int vc_attest_and_connect(vc_t *vc) {
    char enclave_name[7+1];
    uint8_t enclave_cert_hash[32];
    size_t enclave_cert_hash_len = 32;
    int err = vc_attest(
            enclave_name, 7+1,
            enclave_cert_hash, &enclave_cert_hash_len);
    if (err) {
        return err;
    }

    err = vc_connect(vc,
            enclave_name, 
            enclave_cert_hash, enclave_cert_hash_len);
    if (err) {
        return err;
    }

    return 0;
}

