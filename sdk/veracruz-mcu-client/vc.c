/*
 * Veracruz client aimed at microcontrollers, built in Zephyr OS
 *
 * ## Authors
 *
 * The Veracruz Development Team.
 *
 * ## Licensing and copyright notice
 *
 * See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
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


//// Veracruz session handling ////

// connect mbedtls's debug output to veracruz-mcu-client's logging output
static void mbedtls_debug(void *ctx, int level,
        const char *file, int line,
        const char *str) {
    if (level <= 1) {
        VC_LOG("%s", str);
    }
}

// provide cryptographically secure random bytes from Zephyr's random subsys
static int vc_rawrng(void *p,
        uint8_t *buf, size_t len) {
    // We fall back to non-cryptographic RNG if the test random number
    // generator is defined, this is required for qemu-based simulations,
    // but not for native_posix
    //
    // This may be a bug in the qemu-based implementations, since the
    // documentation for CONFIG_TEST_RANDOM_GENERATOR warns it should only
    // be used for testing purposes
    //
    // Don't worry, Zephyr already outputs warnings when this config is defined
    //
    #ifdef CONFIG_TEST_RANDOM_GENERATOR
        sys_rand_get(buf, len);
    #else
        // this is Zephyr's cryptographically secure RNG
        sys_csrand_get(buf, len);
    #endif
    return 0;
}

// raw send over the tunneled TLS session
//
// Note that the tunneled TLS session goes over HTTP POST requests,
// which is a request+response protocol. This means we aren't actuall
// asynchronous, and vc_rawsend also handles recieved new data from the
// POST's response. This is stored in vc->recv_buf to be later processed
// in vc_rawrecv
static ssize_t vc_rawsend(void *p,
        const uint8_t *buf, size_t len) {
    vc_t *vc = p;

    if (vc->recv_len != 0) {
        VC_LOGLN("attemped to send while %d bytes are unrecved, "
            "this should not happen", vc->recv_len);
        return -EBUSY;
    }

    // encode with base64 + id (0)
    ssize_t data_len = 0;
    ssize_t res = snprintf(vc->send_buf, VC_SEND_BUFFER_SIZE,
            "%d ", vc->session_id);
    if (res < 0) {
        VC_LOGLN("formatting failed (%d)", res);
        return res;
    }
    data_len += res;
    res = base64_encode(
        buf, len,
        &vc->send_buf[data_len], VC_SEND_BUFFER_SIZE-data_len);
    if (res < 0) {
        VC_LOGLN("base64_encode failed (%d)", res);
        return res;
    }
    data_len += res;

    // send data over HTTP POST
    VC_LOGXXD("sending to %s:%d:",
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            vc->send_buf,
            data_len);
    VC_LOGLN("veracruz_server -> POST /runtime_manager, %d bytes", data_len);
    ssize_t recv_len = http_post(
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            "/runtime_manager",
            vc->send_buf,
            data_len,
            vc->recv_buf,
            VC_RECV_BUFFER_SIZE);
    if (recv_len < 0) {
        VC_LOGLN("http_post failed (%d)", recv_len);
        return recv_len;
    }
    VC_LOGLN("veracruz_server <- 200 OK, %d bytes", recv_len);

    if (recv_len == 0) {
        // done, recieved nothing
        return len;
    }

    VC_LOGXXD("ssl session: recv:", vc->recv_buf, recv_len);

    // null terminate to make parsing a bit easier
    vc->recv_buf[recv_len] = '\0';

    // we have a bit of parsing to do, first decode session id
    const uint8_t *parsing = vc->recv_buf;
    bool session_id_was_zero = vc->session_id == 0;
    vc->session_id = strtol(parsing, (char **)&parsing, 10);
    if (parsing == vc->recv_buf) {
        VC_LOGLN("failed to parse session id");
        return -EILSEQ;
    }
    // skip space
    parsing += 1;
    if (session_id_was_zero) {
        VC_LOGLN("\033[32mestablished session id:\033[m %d", vc->session_id);
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
            VC_LOGLN("base64_decode failed (%d)", res);
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

    VC_LOGXXD("ssl session: parsed:", vc->recv_pos, vc->recv_len);

    // done!
    return len;
}

// raw recv over the tunneled TLS session
//
// Note that the tunneled TLS session goes over HTTP POST requests,
// which is a request+response protocol. This means we aren't actuall
// asynchronous, and vc_rawrecv just uses the data stored in vc->recv_buf
// by vc_rawsend.
//
// As a side-effect, if there is no data left in this buffer the only option
// we have is to immediately timeout.
static ssize_t vc_rawrecv(void *p,
        uint8_t *buf, size_t len,
        uint32_t timeout) {
    vc_t *vc = p;

    if (vc->recv_len == 0) {
        // no data available? since we communicate over POSTs,
        // we'll never have data available
        VC_LOGLN("attempted to recv with no data available, timeout");
        return MBEDTLS_ERR_SSL_TIMEOUT;
    }

    size_t diff = (len < vc->recv_len) ? len : vc->recv_len;
    memcpy(buf, vc->recv_pos, diff);
    vc->recv_pos += diff;
    vc->recv_len -= diff;
    return diff;
}

// Verify the runtime hash stored in the Veracruz server certificate
//
// This is mostly the asn1 parsing needed to extract the extension field
// to compare against our set of known values (generated by
// policy_to_header.py). The reason we need to do this is because mbedtls
// does not support parsing of custom extensions
static int vc_verify_runtime_hash(vc_t *vc, const mbedtls_x509_crt *peer) {
    VC_LOGLN("verifying runtime hash");

    VC_LOGXXD("extensions:", peer->v3_ext.p, peer->v3_ext.len);

    // check each extension
    uint8_t *ext_seq_ptr = peer->v3_ext.p;
    uint8_t *ext_seq_end = ext_seq_ptr + peer->v3_ext.len;

    // skip seq header
    ext_seq_ptr++;
    int err = mbedtls_asn1_get_len(&ext_seq_ptr, ext_seq_end, &(size_t){0});
    if (err) {
        VC_LOGLN("asn1 parsing failed (%d)", err);
        return err;
    }

    while (ext_seq_ptr < ext_seq_end) {
        uint8_t tag = *ext_seq_ptr++;
        size_t len;
        err = mbedtls_asn1_get_len(&ext_seq_ptr, ext_seq_end, &len);
        if (err) {
            VC_LOGLN("asn1 parsing failed (%d)", err);
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
                    VC_LOGLN("asn1 parsing failed (%d)", err);
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
                        VC_LOGLN("asn1 parsing failed (%d)", err);
                        return err;
                    }

                    if (tag == MBEDTLS_ASN1_OCTET_STRING) {
                        // finally found our octet string, does it match?
                        VC_LOGHEX("found:", ext_ptr, len);

                        // check against known runtime hashes
                        if (len == 32) {
                            for (int i = 0; i < sizeof(VC_RUNTIME_HASHES)/32; i++) {
                                if (memcmp(ext_ptr, VC_RUNTIME_HASHES[i], 32) == 0) {
                                    VC_LOGHEX("\033[32mverified runtime hash:\033[m",
                                            ext_ptr, len);
                                    return 0;
                                }
                            }
                        }

                        VC_LOGLN("runtime hash mismatch");
                        return -EBADE;
                    }

                    ext_ptr += len;
                }
            }
        }

        ext_seq_ptr += len;
    }

    VC_LOGLN("no runtime hash?");
    return -EBADE;
}

int vc_connect(vc_t *vc) {
    // some setup
    vc->session_id = 0;
    vc->recv_len = 0;

    // check that requested ciphersuite is available, this can fail if
    // the ciphersuite isn't enabled in mbedtls's configuration
    if (mbedtls_ssl_ciphersuite_from_id(VC_CIPHERSUITE) == NULL) {
        VC_LOGLN("required ciphersuite unavailable, "
                "is mbedtls configured correctly?");
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
        VC_LOGLN("failed to parse client cert (%d)", err);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    mbedtls_pk_init(&vc->client_key);
    err = mbedtls_pk_parse_key(&vc->client_key,
            VC_CLIENT_KEY_DER, sizeof(VC_CLIENT_KEY_DER),
            NULL, 0);
    if (err) {
        VC_LOGLN("failed to parse client key (%d)", err);
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
        VC_LOGLN("failed to parse client cert (%d)", err);
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
        VC_LOGLN("failed to configure SSL (%d)", err);
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
        VC_LOGLN("failed to setup SSL session (%d)", err);
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
        VC_LOGLN("failed to setup SSL session (%d)", err);
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
    VC_LOGLN("beginning TLS handshake with enclave{%s:%d}",
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    VC_LOGHEX("policy hash:", VC_POLICY_HASH, sizeof(VC_POLICY_HASH));
    VC_LOGHEX("client cert hash:", VC_CLIENT_CERT_HASH, sizeof(VC_CLIENT_CERT_HASH));
    VC_LOGHEX("CA cert hash:", VC_CA_CERT_HASH, sizeof(VC_CA_CERT_HASH));
    err = mbedtls_ssl_handshake(&vc->session);
    if (err) {
        VC_LOGLN("mbedtls_ssl_handshake failed (%d)", err);
        mbedtls_ssl_free(&vc->session);
        mbedtls_ssl_config_free(&vc->session_cfg);
        mbedtls_pk_free(&vc->client_key);
        mbedtls_x509_crt_free(&vc->client_cert);
        free(vc->recv_buf);
        free(vc->send_buf);
        return err;
    }

    // success!
    VC_LOGLN("\033[32mestablished TLS session with enclave{%s:%d}\033[m",
            VC_SERVER_HOST,
            VC_SERVER_PORT);

    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&vc->session);

    VC_LOGXXD("enclave cert:", peer->raw.p, peer->raw.len);

    // verify runtime hash
    err = vc_verify_runtime_hash(vc, peer);
    if (err) {
        vc_close(vc);
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

// helper for encoding dynamic-length bytes/strings
struct const_bytes {
    const uint8_t *buf;
    size_t len;
};

struct bytes {
    uint8_t *buf;
    size_t len;
};

// protobuf encoding for encoding strings to the given field
static bool vc_encode_bytes(
        pb_ostream_t *stream,
        const pb_field_iter_t *field,
        void *const *arg) {
    if (!pb_encode_tag_for_field(stream, field))
        return false;

    struct const_bytes *b = *arg;
    return pb_encode_string(stream, b->buf, b->len);
}

// Ok this is a weird one, but common enough to warrant its
// own function. 
//
// vc_ssl_communicate handles the common send+recv loop found
// in Veracruz. It takes a buffer which may be partially full of
// data, sends it to the Veracruz instances over SSL, and retrieves
// its response. Parsing is left up to the caller.
//
// To handle this there are three different sizes flying around, buf_len
// is the length of data in the buffer to be sent, buf_cap is the capacity
// of the buffer to recieve data, and returned is the amount of data actually
// recieved from Veracruz.
static ssize_t vc_ssl_communicate(vc_t *vc,
        const char *func, const char *name,
        uint8_t *buf, size_t buf_len, size_t buf_cap) {
    VC_LOGXXD("%s: %s:", buf, len, func, name);

    // send to Veracruz
    size_t written = 0;
    while (written < buf_len) {
        int res = mbedtls_ssl_write(&vc->session,
                &buf[written], buf_len-written);
        if (res < 0) {
            VC_LOGLN("mbedtls_ssl_write failed (%d)", res);
            return res;
        }

        // if send is fragmented, update with a progress message
        if (written != 0) {
            VC_LOGLN("%s: %d/%d bytes", func, written+res, buf_len);
        }
        written += res;
    }

    // get Veracruz's response
    int res = mbedtls_ssl_read(&vc->session, buf, buf_cap);
    if (res < 0) {
        VC_LOGLN("mbedtls_ssl_read failed (%d)", res);
        return res;
    }

    VC_LOGXXD("%s: response:", buf, res, func);

    return res;
}

// Send data to a Veracruz instance over the tunneled TLS session
//
// vc       - Veracruz client state
// name     - The name of the file to write to in the enclave
// data     - Buffer containing the data to send
// data_len - Size of the data buffer
//
// Returns 0 on success, or a negative error code on failure
int vc_send_data(vc_t *vc,
        const char *name,
        const uint8_t *data,
        size_t data_len) {
    VC_LOGLN("sending data to enclave{%s:%d}/%s, %d bytes",
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            name, data_len);
    // construct data protobuf
    Tp_RuntimeManagerRequest send_data = {
        .which_message_oneof = Tp_RuntimeManagerRequest_data_tag,
        .message_oneof.data.file_name.funcs.encode = vc_encode_bytes,
        .message_oneof.data.file_name.arg = &(struct const_bytes){
            .buf = name,
            .len = strlen(name),
        },
        .message_oneof.data.data.funcs.encode = vc_encode_bytes,
        .message_oneof.data.data.arg = &(struct const_bytes){
            .buf = data,
            .len = data_len,
        },
    };

    // figure out how much of a buffer to allocate, this needs to hold our
    // sent data + the response, response is fairly small
    size_t encoded_size = 0;
    pb_get_encoded_size(&encoded_size, &Tp_RuntimeManagerRequest_msg, &send_data);
    size_t proto_len = (32 > encoded_size) ? 32 : encoded_size;
    // heh, proto_buf
    uint8_t *proto_buf = malloc(proto_len);
    if (!proto_buf) {
        return -ENOMEM;
    }

    // encode
    pb_ostream_t proto_stream = pb_ostream_from_buffer(
            proto_buf, proto_len);
    bool success = pb_encode(&proto_stream, &Tp_RuntimeManagerRequest_msg, &send_data);
    if (!success) {
        VC_LOGLN("pb_encode failed (%s)", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    // communicate over SSL
    ssize_t res = vc_ssl_communicate(vc, "vc_send_data", name,
            proto_buf, proto_stream.bytes_written, proto_len);
    if (res < 0) {
        free(proto_buf);
        return res;
    }

    // parse
    Tp_RuntimeManagerResponse response;
    pb_istream_t resp_stream = pb_istream_from_buffer(
            proto_buf, res);
    success = pb_decode(&resp_stream, &Tp_RuntimeManagerResponse_msg, &response);
    if (!success) {
        VC_LOGLN("pb_decode failed (%s)", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    free(proto_buf);

    // did server send success?
    if (response.status != Tp_ResponseStatus_SUCCESS) {
        VC_LOGLN("vc_send_data successfully failed! (%d)", response.status);
        return -EACCES;
    }

    VC_LOGLN("enclave{%s:%d} responded with success",
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    VC_LOGLN("\033[32muploaded %d bytes to enclave{%s:%d}/%s\033[m",
            data_len,
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            name);
    return 0;
}

// Send a program to a Veracruz instance over the tunneled TLS session
//
// vc          - Veracruz client state
// name        - The name of the file to write to in the enclave
// program     - Buffer containing the program to send
// program_len - Size of the program buffer
//
// Returns 0 on success, or a negative error code on failure
int vc_send_program(vc_t *vc,
        const char *name,
        const uint8_t *program,
        size_t program_len) {
    VC_LOGLN("sending program to enclave{%s:%d}/%s, %d bytes",
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            name, program_len);
    // construct program protobuf
    Tp_RuntimeManagerRequest send_program = {
        .which_message_oneof = Tp_RuntimeManagerRequest_write_file_tag,
        .message_oneof.data.file_name.funcs.encode = vc_encode_bytes,
        .message_oneof.data.file_name.arg = &(struct const_bytes){
            .buf = name,
            .len = strlen(name),
        },
        .message_oneof.data.data.funcs.encode = vc_encode_bytes,
        .message_oneof.data.data.arg = &(struct const_bytes){
            .buf = program,
            .len = program_len,
        },
    };

    // figure out how much of a buffer to allocate, this needs to hold our
    // sent program + the response, response is fairly small
    size_t encoded_size = 0;
    pb_get_encoded_size(&encoded_size, &Tp_RuntimeManagerRequest_msg, &send_program);
    size_t proto_len = (32 > encoded_size) ? 32 : encoded_size;
    // heh, proto_buf
    uint8_t *proto_buf = malloc(proto_len);
    if (!proto_buf) {
        return -ENOMEM;
    }

    // encode
    pb_ostream_t proto_stream = pb_ostream_from_buffer(
            proto_buf, proto_len);
    bool success = pb_encode(&proto_stream, &Tp_RuntimeManagerRequest_msg, &send_program);
    if (!success) {
        VC_LOGLN("pb_encode failed (%s)", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    // communicate over SSL
    ssize_t res = vc_ssl_communicate(vc, "vc_send_program", name,
            proto_buf, proto_stream.bytes_written, proto_len);
    if (res < 0) {
        free(proto_buf);
        return res;
    }

    // parse
    Tp_RuntimeManagerResponse response;
    pb_istream_t resp_stream = pb_istream_from_buffer(
            proto_buf, res);
    success = pb_decode(&resp_stream, &Tp_RuntimeManagerResponse_msg, &response);
    if (!success) {
        VC_LOGLN("pb_decode failed (%s)", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    free(proto_buf);

    // did server send success?
    if (response.status != Tp_ResponseStatus_SUCCESS) {
        VC_LOGLN("vc_send_program successfully failed! (%d)", response.status);
        return -EACCES;
    }

    VC_LOGLN("enclave{%s:%d} responded with success",
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    VC_LOGLN("\033[32muploaded %d bytes to enclave{%s:%d}/%s\033[m",
            program_len,
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            name);
    return 0;
}

// Request a result from a Veracruz instance over the tunneled TLS session
//
// vc         - Veracruz client state
// name       - The name of the file to read from the enclave
// result     - Buffer to be filled with the result
// result_len - Size of the result buffer
//
// Returns the number of bytes written, or a negative error code on failure
static bool vc_request_result_decode(
        pb_istream_t *stream, const pb_field_t *field, void **arg) {
    struct bytes *result = *arg;
    if (stream->bytes_left > result->len) {
        VC_LOGLN("result size exceeded buffer (%d > %d)",
            stream->bytes_left, result->len);
        return false;
    }

    result->len = stream->bytes_left;
    return pb_read(stream, result->buf, result->len);
}

ssize_t vc_request_result(vc_t *vc,
        const char *name,
        uint8_t *result,
        size_t result_len) {
    VC_LOGLN("requesting result from enclave{%s:%d}/%s",
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            name);
    // construct program protobuf
    Tp_RuntimeManagerRequest request_result = {
        .which_message_oneof = Tp_RuntimeManagerRequest_request_result_tag,
        .message_oneof.request_result.file_name.funcs.encode = vc_encode_bytes,
        .message_oneof.request_result.file_name.arg = &(struct const_bytes){
            .buf = name,
            .len = strlen(name),
        },
    };

    // figure out how much of a buffer to allocate, this needs to hold our
    // sent program + the response, response is fairly small
    size_t encoded_size = 0;
    pb_get_encoded_size(&encoded_size, &Tp_RuntimeManagerRequest_msg, &request_result);
    size_t proto_len = (VC_RECV_BUFFER_SIZE > encoded_size)
            ? VC_RECV_BUFFER_SIZE : encoded_size;
    // heh, proto_buf
    uint8_t *proto_buf = malloc(proto_len);
    if (!proto_buf) {
        return -ENOMEM;
    }

    // encode
    pb_ostream_t proto_stream = pb_ostream_from_buffer(
            proto_buf, proto_len);
    bool success = pb_encode(&proto_stream, &Tp_RuntimeManagerRequest_msg, &request_result);
    if (!success) {
        VC_LOGLN("pb_encode failed (%s)", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    // communicate over SSL
    ssize_t res = vc_ssl_communicate(vc, "vc_request_result", name,
            proto_buf, proto_stream.bytes_written, proto_len);
    if (res < 0) {
        free(proto_buf);
        return res;
    }

    // parse
    //
    // note that RuntimeManagerResponse is configured to not use unions,
    // this is due to a limitation in nanopb that requires no_union for callbacks
    // to work, otherwise we would need more memory allocations
    //
    // https://github.com/nanopb/nanopb/issues/572
    //
    struct bytes result_bytes = {
        .buf = result,
        .len = result_len,
    };
    Tp_RuntimeManagerResponse response = {
        .result.data.funcs.decode = vc_request_result_decode,
        .result.data.arg = &result_bytes,
    };
    pb_istream_t resp_stream = pb_istream_from_buffer(
            proto_buf, res);
    success = pb_decode(&resp_stream, &Tp_RuntimeManagerResponse_msg, &response);
    if (!success) {
        VC_LOGLN("pb_decode failed (%s)", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    free(proto_buf);
    result_len = result_bytes.len;

    // did server send success?
    if (response.status != Tp_ResponseStatus_SUCCESS) {
        VC_LOGLN("vc_request_result successfully failed! (%d)", response.status);
        return -EACCES;
    }

    // did server send a result?
    //if (response.which_message_oneof != Tp_RuntimeManagerResponse_result_tag) {
    if (!response.has_result) {
        VC_LOGLN("vc_request_result did not respond with a result");
        return -EILSEQ;
    }

    VC_LOGLN("enclave{%s:%d} responded with success",
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    VC_LOGLN("\033[32mdownloaded %d bytes from enclave{%s:%d}/%s\033[m",
            result_len,
            VC_SERVER_HOST,
            VC_SERVER_PORT,
            name);
    return result_len;
}

// Request the shutdown of a Veracruz instance
//
// vc - Veracruz client state
//
// Returns 0 on succes, or a negative error code on failure
int vc_request_shutdown(vc_t *vc) {
    VC_LOGLN("requesting shutdown from enclave{%s:%d}",
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    // construct program protobuf
    Tp_RuntimeManagerRequest request_result = {
        .which_message_oneof = Tp_RuntimeManagerRequest_request_shutdown_tag,
    };

    // figure out how much of a buffer to allocate
    size_t encoded_size = 0;
    pb_get_encoded_size(&encoded_size, &Tp_RuntimeManagerRequest_msg, &request_result);
    size_t proto_len = encoded_size;
    // heh, proto_buf
    uint8_t *proto_buf = malloc(proto_len);
    if (!proto_buf) {
        return -ENOMEM;
    }

    // encode
    pb_ostream_t proto_stream = pb_ostream_from_buffer(
            proto_buf, proto_len);
    bool success = pb_encode(&proto_stream, &Tp_RuntimeManagerRequest_msg, &request_result);
    if (!success) {
        VC_LOGLN("pb_encode failed (%s)", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    // communicate over SSL
    ssize_t res = vc_ssl_communicate(vc, "vc_request_shutdown", "shutdown",
            proto_buf, proto_stream.bytes_written, proto_len);
    if (res < 0) {
        free(proto_buf);
        return res;
    }

    // parse
    Tp_RuntimeManagerResponse response;
    pb_istream_t resp_stream = pb_istream_from_buffer(
            proto_buf, res);
    success = pb_decode(&resp_stream, &Tp_RuntimeManagerResponse_msg, &response);
    if (!success) {
        VC_LOGLN("pb_decode failed (%s)", proto_stream.errmsg);
        free(proto_buf);
        return -EILSEQ;
    }

    free(proto_buf);

    // did server send success?
    if (response.status != Tp_ResponseStatus_SUCCESS) {
        VC_LOGLN("vc_request_shutdown successfully failed! (%d)", response.status);
        return -EACCES;
    }

    VC_LOGLN("enclave{%s:%d} responded with success",
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    VC_LOGLN("\033[32mshutdown enclave{%s:%d}\033[m",
            VC_SERVER_HOST,
            VC_SERVER_PORT);
    return 0;
}
