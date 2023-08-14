/*
 * Veracruz client aimed at microcontrollers, built in Zephyr OS
 *
 * Note that there are very few arguments to these functions, the Veracruz
 * client uses a static policy.json file that is expected preprocessed into
 * a policy.h file (see policy_to_header.py).
 *
 * TODO provide a config struct as an alternative to static configuration?
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

#ifndef VC_H
#define VC_H

#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/ssl.h>

// Veracruz's custom extension field containing the runtime hash
#ifndef VC_RUNTIME_HASH_EXTENSION_ID
#define VC_RUNTIME_HASH_EXTENSION_ID ((const uint8_t[3]){85, 30, 1})
#endif

// define for log/logln
#ifndef VC_LOG
    #ifdef CONFIG_VC_LOG
        #define VC_LOG_(fmt, ...)     printf(fmt "%s", __VA_ARGS__)
        #define VC_LOG(...)           VC_LOG_(__VA_ARGS__, "")
        #define VC_LOGLN_(fmt, ...)   printf(fmt "%s\n", __VA_ARGS__)
        #define VC_LOGLN(...)         VC_LOGLN_(__VA_ARGS__, "")
    #else
        #define VC_LOG(...)
        #define VC_LOGLN(...)
    #endif
#endif

// define for logging large hex strings
#ifndef VC_LOGHEX
    #ifdef CONFIG_VC_LOG
        #define VC_LOGHEX_(fmt, buf, len, ...) \
            do { \
                VC_LOG(fmt "%s ", __VA_ARGS__); \
                hex(buf, len); \
                VC_LOG("\n"); \
            } while(0)
        #define VC_LOGHEX(...) VC_LOGHEX_(__VA_ARGS__, "")
    #else
        #define VC_LOGHEX(...)
    #endif
#endif

// define for hex dumps of various internal state
#ifndef VC_LOGXXD
    #ifdef CONFIG_VC_LOG_HEXDUMPS
        #define VC_LOGXXD_(fmt, buf, len, ...) \
            do { \
                VC_LOG(fmt "%s\n", __VA_ARGS__); \
                xxd(buf, len); \
            } while(0)
        #define VC_LOGXXD(...) VC_LOGXXD_(__VA_ARGS__, "")
    #else
        #define VC_LOGXXD(...)
    #endif
#endif
    
// other configuration variables, CONFIG_* is provided by Zephyr+Kconfig
#ifndef VC_SEND_BUFFER_SIZE
    #ifdef CONFIG_VC_SEND_BUFFER_SIZE
    #define VC_SEND_BUFFER_SIZE CONFIG_VC_SEND_BUFFER_SIZE
    #else
    #define VC_SEND_BUFFER_SIZE (2*1024)
    #endif
#endif

#ifndef VC_RECV_BUFFER_SIZE
    #ifdef CONFIG_VC_RECV_BUFFER_SIZE
    #define VC_RECV_BUFFER_SIZE CONFIG_VC_RECV_BUFFER_SIZE
    #else
    #define VC_RECV_BUFFER_SIZE (4*1024)
    #endif
#endif

// Veracruz client state
typedef struct vc {
    // Veracruz state
    int session_id;
    const uint8_t *recv_pos;
    size_t recv_len;

    // TLS state
    mbedtls_ssl_context session;
    mbedtls_ssl_config session_cfg;
    mbedtls_x509_crt ca_cert;

    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;

    // buffers for shuffling TLS data around
    uint8_t *send_buf;
    uint8_t *recv_buf;
} vc_t;


// Connect and verify attestation of a Veracruz enclave
//
// Connect, and verify that the certificate chain of our enclave was signed
// by the PAS root CA. This implies that the PAS has succesfully attested the
// enclave running on the server.
//
// Once the server has been attested, we then establish a TLS connection directly
// into the runtime inside the enclave. Through this we can send/recv data
// to/from the computation
//
// vc - Veracruz client state
//
// Returns 0 on success, or a negative error code on failure
int vc_connect(vc_t *vc);

// Disconnect and clean up memory
//
// vc - Veracruz client state
//
// Note, even if an error is returned, memory is still cleaned up
//
// Returns 0 on success, or a negative error code on failure
int vc_close(vc_t *vc);

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
        size_t data_len);

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
        size_t program_len);

// Request a result from a Veracruz instance over the tunneled TLS session
//
// vc         - Veracruz client state
// name       - The name of the file to read from the enclave
// result     - Buffer to be filled with the result
// result_len - Size of the result buffer
//
// Returns the number of bytes written, or a negative error code on failure
ssize_t vc_request_result(vc_t *vc,
        const char *name,
        uint8_t *result,
        size_t result_len);

// Request the shutdown of a Veracruz instance
//
// vc - Veracruz client state
//
// Returns 0 on succes, or a negative error code on failure
int vc_request_shutdown(vc_t *vc);


#endif
