/*
 * Veracruz client aimed at microcontrollers, built in Zephyr OS
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


//// Veracruz session handling ////
static void mbedtls_debug(void *ctx, int level,
        const char *file, int line,
        const char *str) {
    if (level <= 1) {
        printf("%s", str);
    }
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
    #ifdef VC_DUMP_INFO
        printf("sending to %s:%d:\n",
                VC_SERVER_HOST,
                VC_SERVER_PORT);
        xxd(vc->send_buf, data_len);
    #endif
    printf("veracruz_server -> POST /runtime_manager, %d bytes\n", data_len);
    ssize_t recv_len = http_post(
            VC_SERVER_HOST,
            VC_SERVER_PORT,
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

    if (recv_len == 0) {
        // done, recieved nothing
        return len;
    }

    #ifdef VC_DUMP_INFO
        printf("ssl session: recv:\n");
        xxd(vc->recv_buf, recv_len);
    #endif

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

    #ifdef VC_DUMP_INFO
        printf("ssl session: parsed:\n");
        xxd(vc->recv_pos, vc->recv_len);
    #endif

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

    #ifdef VC_DUMP_INFO
        printf("extensions:\n");
        xxd(peer->v3_ext.p, peer->v3_ext.len);
    #endif

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

                        // check against known runtime hashes
                        if (len == 32) {
                            for (int i = 0; i < sizeof(VC_RUNTIME_HASHES)/32; i++) {
                                if (memcmp(ext_ptr, VC_RUNTIME_HASHES[i], 32) == 0) {
                                    printf("\033[32mverified runtime hash:\033[m ");
                                    hex(ext_ptr, len);
                                    printf("\n");
                                    return 0;
                                }
                            }
                        }

                        printf("runtime hash mismatch\n");
                        return -EBADE;
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

int vc_connect(vc_t *vc) {
    // some setup
    vc->session_id = 0;
    vc->recv_len = 0;

    // check that requested ciphersuite is available, this can fail if
    // the ciphersuite isn't enabled in mbedtls's configuration
    if (mbedtls_ssl_ciphersuite_from_id(VC_CIPHERSUITE) == NULL) {
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
            VC_CLIENT_CERT_DER, sizeof(VC_CLIENT_CERT_DER));
    if (err) {
        printf("failed to parse client cert (%d)\n", err);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    mbedtls_pk_init(&vc->client_key);
    err = mbedtls_pk_parse_key(&vc->client_key,
            VC_CLIENT_KEY_DER, sizeof(VC_CLIENT_KEY_DER),
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
            VC_CA_CERT_DER, sizeof(VC_CA_CERT_DER));
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

    // register the proxy attestation server as our CA
    mbedtls_ssl_conf_ca_chain(&vc->session_cfg, &vc->ca_cert, NULL);

    // other configuration
    mbedtls_ssl_conf_rng(&vc->session_cfg, vc_rawrng, NULL);
    mbedtls_ssl_conf_ciphersuites(&vc->session_cfg, VC_CIPHERSUITES);

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
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    printf("policy hash: ");
    hex(VC_POLICY_HASH, sizeof(VC_POLICY_HASH));
    printf("\n");
    printf("client cert hash: ");
    hex(VC_CLIENT_CERT_HASH, sizeof(VC_CLIENT_CERT_HASH));
    printf("\n");
    printf("CA cert hash: ");
    hex(VC_CA_CERT_HASH, sizeof(VC_CA_CERT_HASH));
    printf("\n");
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
            VC_SERVER_HOST,
            VC_SERVER_PORT);

    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&vc->session);

    #ifdef VC_DUMP_INFO
        printf("enclave cert:\n");
        xxd(peer->raw.p, peer->raw.len);
    #endif

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
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            name, data_len);
    // construct data protobuf
    Tp_RuntimeManagerRequest send_data = {
        .which_message_oneof = Tp_RuntimeManagerRequest_data_tag,
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
    pb_get_encoded_size(&encoded_size, &Tp_RuntimeManagerRequest_msg, &send_data);
    size_t proto_len = (32 > encoded_size) ? 32 : encoded_size;
    // heh
    uint8_t *proto_buf = malloc(proto_len);

    // encode
    pb_ostream_t proto_stream = pb_ostream_from_buffer(
            proto_buf, proto_len);
    bool success = pb_encode(&proto_stream, &Tp_RuntimeManagerRequest_msg, &send_data);
    if (!success) {
        printf("pb_encode failed (%s)\n", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    #ifdef VC_DUMP_INFO
        printf("send_data: %s:\n", name);
        xxd(proto_buf, proto_stream.bytes_written);
    #endif

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

    #ifdef VC_DUMP_INFO
        printf("send_data: response:\n");
        xxd(proto_buf, res);
    #endif

    // parse
    Tp_RuntimeManagerResponse response;
    pb_istream_t resp_stream = pb_istream_from_buffer(
            proto_buf, res);
    success = pb_decode(&resp_stream, &Tp_RuntimeManagerResponse_msg, &response);
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
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    printf("\033[32muploaded %d bytes to enclave{%s:%d}/%s\033[m\n",
            data_len,
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            name);
    k_sleep(Z_TIMEOUT_MS(DELAY*1000));
    return 0;
}


