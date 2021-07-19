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
#include "clap.h"


//// attestation ////
int vc_attest(
        char *enclave_name, size_t enclave_name_len,
        uint8_t *enclave_cert_hash, size_t *enclave_cert_hash_len) {
    printf("attesting %s:%d\n",
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT);

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
    // TODO VERACRUZ_POLICY_HASH should be raw bytes
    printf("policy: %s\n", VERACRUZ_POLICY_HASH);
    printf("challenge: ");
    hex(challenge, sizeof(challenge));
    printf("\n");

    // construct attestation token request
    Tp_MexicoCityRequest request = {
        .which_message_oneof = Tp_MexicoCityRequest_request_proxy_psa_attestation_token_tag
    };
    memcpy(request.message_oneof.request_proxy_psa_attestation_token.challenge,
            challenge, sizeof(challenge));

    // encode
    // TODO this could be smaller, but instead could we tie protobuf encoding
    // directly into our GET function?
    uint8_t request_buf[256];
    memset(request_buf, 0, sizeof(request_buf));
    pb_ostream_t request_stream = pb_ostream_from_buffer(
            request_buf, sizeof(request_buf));
    bool success = pb_encode(&request_stream, &Tp_MexicoCityRequest_msg, &request);
    if (!success) {
        // TODO we can reduce code size by removing these error messages
        printf("pb_encode failed (%s)\n", request_stream.errmsg);
        return -EILSEQ;
    }

    // convert base64
    ssize_t request_len = base64_encode(
            request_buf, request_stream.bytes_written, 
            request_buf, sizeof(request_buf));
    if (request_len < 0) {
        printf("base64_encode failed (%d)\n", request_len);
        return request_len;
    }

//    printf("request:\n");
//    xxd(request_buf, request_len);

    // POST challenge
//    printf("connecting to %s:%d...\n",
//            VERACRUZ_SERVER_HOST,
//            VERACRUZ_SERVER_PORT);
    uint8_t pat_buf[1024];
    memset(pat_buf, 0, sizeof(pat_buf));
    printf("veracruz_server -> POST /veracruz_server, %d bytes\n", request_len);
    ssize_t pat_len = http_post(
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT,
            "/veracruz_server",
            request_buf,
            request_len,
            pat_buf,
            sizeof(pat_buf));
    if (pat_len < 0) {
        printf("http_post failed (%d)\n", pat_len);
        return pat_len;
    }
    printf("veracruz_server <- 200 OK, %d bytes\n", pat_len);
//    printf("attest: challenge response:\n");
//    xxd(pat_buf, pat_len);

    // forward to proxy attestation server
//    printf("connecting to %s:%d...\n",
//            PROXY_ATTESTATION_SERVER_HOST,
//            PROXY_ATTESTATION_SERVER_PORT);
    printf("forwarding challenge response to %s:%d\n",
            PROXY_ATTESTATION_SERVER_HOST,
            PROXY_ATTESTATION_SERVER_PORT);
    uint8_t response_buf[256];
    // TODO we shouldn't need to zero this, but we do, fix?
    // TODO the issue is base64 decoding with no null-terminator
    memset(response_buf, 0, sizeof(response_buf));
    printf("proxy_attestation_server -> POST /VerifyPAT, %d bytes\n", pat_len);
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
    printf("proxy_attestation_server <- 200 OK, %d bytes\n", response_len);

//    printf("http_post -> %d\n", response_len);
//    printf("attest: PAT response:\n");
//    xxd(response_buf, response_len);

    // decode base64
    ssize_t verif_len = base64_decode(
            response_buf, sizeof(response_buf),
            response_buf, sizeof(response_buf));
    if (verif_len < 0) {
        printf("base64_decode failed (%d)\n", verif_len);
        return verif_len;
    }
    
//    printf("attest: PAT decoded response:\n");
//    xxd(response_buf, verif_len);

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

    printf("\033[32msuccessfully attested %s:%d\033[m\n",
        VERACRUZ_SERVER_HOST,
        VERACRUZ_SERVER_PORT);
    printf("\033[32menclave name:\033[m %s\n", enclave_name);
    printf("\033[32menclave hash:\033[m ");
    hex(&response_buf[47], 32);
    printf("\n");
    printf("\033[32menclave cert hash:\033[m ");
    hex(enclave_cert_hash, *enclave_cert_hash_len);
    printf("\n");

    k_sleep(Z_TIMEOUT_MS(DELAY*1000));
    return 0;
}


//// Veracruz session handling ////
static void mbedtls_debug(void *ctx, int level,
        const char *file, int line,
        const char *str) {
    if (level <= 1) {
        printf("%s", str);
    }

    //k_sleep(Z_TIMEOUT_MS(1));
//    const char *basename = file;
//    for (int i = 0; file[i]; i++) {
//        if (file[i] == '/') {
//            basename = &file[i+1];
//        }
//    }
//
//    printf("%s:%d %s", basename, line, str);
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
//    printf("sending to %s:%d:\n",
//            VERACRUZ_SERVER_HOST,
//            VERACRUZ_SERVER_PORT);
//    xxd(vc->send_buf, data_len);
    printf("veracruz_server -> POST /runtime_manager, %d bytes\n", data_len);
    ssize_t recv_len = http_post(
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT,
            "/runtime_manager",
            vc->send_buf,
            data_len,
            vc->recv_buf,
            VC_RECV_BUFFER_SIZE);
    if (recv_len < 0) {
        printf("http_post failed (%d)\n", recv_len);
        return recv_len;
    }
    printf("veracruz_server <- 200 OK, %d bytes\n", recv_len);

    //printf("http_post -> %d\n", recv_len);

    if (recv_len == 0) {
        // done, recieved nothing
        return len;
    }

//    printf("ssl session: recv:\n");
//    xxd(vc->recv_buf, recv_len);

    // null terminate to make parsing a bit easier
    vc->recv_buf[recv_len] = '\0';

    // we have a bit of parsing to do, first decode session id
    const uint8_t *parsing = vc->recv_buf;
    bool session_id_was_zero = vc->session_id == 0;
    vc->session_id = strtol(parsing, (char **)&parsing, 10);
    if (parsing == vc->recv_buf) {
        printf("failed to parse session id\n");
        return -EILSEQ;
    }
    // skip space
    parsing += 1;
    if (session_id_was_zero) {
        printf("\033[32mestablished session id:\033[m %d\n", vc->session_id);
    }

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

//    printf("ssl session: parsed:\n");
//    xxd(vc->recv_pos, vc->recv_len);

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

static int vc_verify_runtime_hash(vc_t *vc, const mbedtls_x509_crt *peer) {
    printf("verifying runtime hash\n");
//
//    printf("extensions:\n");
//    xxd(peer->v3_ext.p, peer->v3_ext.len);

    // check each extension
    uint8_t *ext_seq_ptr = peer->v3_ext.p;
    uint8_t *ext_seq_end = ext_seq_ptr + peer->v3_ext.len;

    // skip seq header
    ext_seq_ptr++;
    int err = mbedtls_asn1_get_len(&ext_seq_ptr, ext_seq_end, &(size_t){0});
    if (err) {
        printf("asn1 parsing failed (%d)\n", err);
        return err;
    }

    while (ext_seq_ptr < ext_seq_end) {
        uint8_t tag = *ext_seq_ptr++;
        size_t len;
        err = mbedtls_asn1_get_len(&ext_seq_ptr, ext_seq_end, &len);
        if (err) {
            printf("asn1 parsing failed (%d)\n", err);
            return err;
        }

        if (tag == (MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) {
            bool runtime_hash_found = false;

            // search for our oid
            uint8_t *ext_ptr = ext_seq_ptr;
            uint8_t *ext_end = ext_ptr + len;
            while (ext_ptr < ext_end) {
                uint8_t tag = *ext_ptr++;
                size_t len;
                err = mbedtls_asn1_get_len(&ext_ptr, ext_end, &len);
                if (err) {
                    printf("asn1 parsing failed (%d)\n", err);
                    return err;
                }

                if (tag == MBEDTLS_ASN1_OID) {
                    // TODO move to constant
                    if (memcmp(ext_ptr, VC_RUNTIME_HASH_EXTENSION_ID,
                            sizeof(VC_RUNTIME_HASH_EXTENSION_ID)) == 0) {
                        runtime_hash_found = true;
                    }
                    break;
                }

                ext_ptr += len;
            }

            // found oid for runtime hash, lookup actual hash value
            if (runtime_hash_found) {
                // search for runtime hash
                uint8_t *ext_ptr = ext_seq_ptr;
                uint8_t *ext_end = ext_ptr + len;
                while (ext_ptr < ext_end) {
                    uint8_t tag = *ext_ptr++;
                    size_t len;
                    err = mbedtls_asn1_get_len(&ext_ptr, ext_end, &len);
                    if (err) {
                        printf("asn1 parsing failed (%d)\n", err);
                        return err;
                    }

                    if (tag == MBEDTLS_ASN1_OCTET_STRING) {
                        // finally found our octet string, does it match?
                        printf("found: ");
                        hex(ext_ptr, len);
                        printf("\n");
                        printf("expected: ");
                        hex(RUNTIME_MANAGER_HASH, sizeof(RUNTIME_MANAGER_HASH));
                        printf("\n");

                        if (len == sizeof(RUNTIME_MANAGER_HASH) &&
                                memcmp(ext_ptr,
                                    RUNTIME_MANAGER_HASH, len) == 0) {
                            
                            printf("\033[32mverified runtime hash:\033[m ");
                            hex(RUNTIME_MANAGER_HASH,
                                sizeof(RUNTIME_MANAGER_HASH));
                            printf("\n");
                            return 0;
                        } else {
                            printf("runtime hash mismatch\n");
                            return -EBADE;
                        }
                    }

                    ext_ptr += len;
                }
            }
        }

        ext_seq_ptr += len;
    }

    printf("no runtime hash?\n");
    return -EBADE;
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

    // parse CA cert
    mbedtls_x509_crt_init(&vc->ca_cert);
    err = mbedtls_x509_crt_parse_der(&vc->ca_cert,
            CA_CERT_DER, sizeof(CA_CERT_DER));
    if (err) {
        printf("failed to parse client cert (%d)\n", err);
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
    //mbedtls_ssl_conf_authmode(&vc->session_cfg, MBEDTLS_SSL_VERIFY_NONE);

    // register the proxy attestation server as our CA
    mbedtls_ssl_conf_ca_chain(&vc->session_cfg, &vc->ca_cert, NULL);

    // other configuration
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
    printf("beginning TLS handshake with enclave{%s:%d}\n",
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT);
    printf("policy hash: %s\n", VERACRUZ_POLICY_HASH); 
    printf("client cert hash: %s\n", CLIENT_CERT_HASH);
    printf("CA cert hash: %s\n", CA_CERT_HASH);
    err = mbedtls_ssl_handshake(&vc->session);
    if (err) {
        printf("mbedtls_ssl_handshake failed (%d)\n", err);
        mbedtls_ssl_free(&vc->session);
        mbedtls_ssl_config_free(&vc->session_cfg);
        mbedtls_pk_free(&vc->client_key);
        mbedtls_x509_crt_free(&vc->client_cert);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    // success!
    printf("\033[32mestablished TLS session with enclave{%s:%d}\033[m\n",
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT);

    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&vc->session);

//    printf("enclave cert:\n");
//    xxd(peer->raw.p, peer->raw.len);

    // verify runtime hash
    err = vc_verify_runtime_hash(vc, peer);
    if (err) {
        vc_close(vc);
        return err;
    }

    k_sleep(Z_TIMEOUT_MS(DELAY*1000));
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

// helper for encoding dynamic-length bytes/strings
struct bytes {
    const void *buf;
    size_t len;
};

static bool vc_encode_bytes(
        pb_ostream_t *stream,
        const pb_field_iter_t *field,
        void *const *arg) {
    if (!pb_encode_tag_for_field(stream, field))
        return false;

    struct bytes *b = *arg;
    return pb_encode_string(stream, b->buf, b->len);
}

int vc_send_data(vc_t *vc,
        const char *name,
        const uint8_t *data,
        size_t data_len) {
    printf("sending data to enclave{%s:%d}/%s, %d bytes\n",
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT,
            name, data_len);
    // construct data protobuf
    Tp_MexicoCityRequest send_data = {
        .which_message_oneof = Tp_MexicoCityRequest_data_tag,
        .message_oneof.data.file_name.funcs.encode = vc_encode_bytes,
        .message_oneof.data.file_name.arg = &(struct bytes){
            .buf = name,
            .len = strlen(name),
        },
        .message_oneof.data.data.funcs.encode = vc_encode_bytes,
        .message_oneof.data.data.arg = &(struct bytes){
            .buf = data,
            .len = data_len,
        },
    };

    // figure out how much of a buffer to allocate, this needs to hold our
    // sent data + the response, response is fairly small and honestly could
    // be smaller
    size_t encoded_size = 0;
    pb_get_encoded_size(&encoded_size, &Tp_MexicoCityRequest_msg, &send_data);
    size_t proto_len = (32 > encoded_size) ? 32 : encoded_size;
    // heh
    uint8_t *proto_buf = malloc(proto_len);

    // encode
    pb_ostream_t proto_stream = pb_ostream_from_buffer(
            proto_buf, proto_len);
    bool success = pb_encode(&proto_stream, &Tp_MexicoCityRequest_msg, &send_data);
    if (!success) {
        // TODO we can reduce code size by removing these error messages
        printf("pb_encode failed (%s)\n", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    // TODO log? can we incrementally log?
//    printf("send_data: %s:\n", name);
//    xxd(proto_buf, proto_stream.bytes_written);

    // send to Veracruz
    int res = mbedtls_ssl_write(&vc->session,
            proto_buf, proto_stream.bytes_written);
    if (res < 0) {
        printf("mbedtls_ssl_write failed (%d)\n", res);
        free(proto_buf);
        return res;
    }

    // get Veracruz's response
    res = mbedtls_ssl_read(&vc->session, proto_buf, proto_len);
    if (res < 0) {
        printf("mbedtls_ssl_read failed (%d)\n", res);
        free(proto_buf);
        return res;
    }

//    printf("send_data: response:\n");
//    xxd(proto_buf, res);

    // parse
    Tp_MexicoCityResponse response;
    pb_istream_t resp_stream = pb_istream_from_buffer(
            proto_buf, res);
    success = pb_decode(&resp_stream, &Tp_MexicoCityResponse_msg, &response);
    if (!success) {
        printf("pb_decode failed (%s)\n", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    free(proto_buf);

    // did server send success?
    if (response.status != Tp_ResponseStatus_SUCCESS) {
        printf("send_data successfully failed! (%d)\n", response.status);
        return -EACCES;
    }

    printf("enclave{%s:%d} responded with success\n",
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT);
    printf("\033[32muploaded %d bytes to enclave{%s:%d}/%s\033[m\n",
            data_len,
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT,
            name);
    k_sleep(Z_TIMEOUT_MS(DELAY*1000));
    return 0;
}


