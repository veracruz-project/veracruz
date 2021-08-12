/*
 * Veracruz client aimed at microcontrollers, built in Zephyr OS
 *
 * Note that there are very few arguments to these functions, the Veracruz
 * client is based on a static policy file that is expected preprocessed into
 * a policy.h file (see policy_to_header.py).
 *
 * TODO config struct?
 *
 */

#ifndef VC_H
#define VC_H

#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/ssl.h>

// define for more output
//#define VC_DUMP_INFO

#ifndef VC_RUNTIME_HASH_EXTENSION_ID
#define VC_RUNTIME_HASH_EXTENSION_ID ((const uint8_t[3]){85, 30, 1})
#endif

#ifndef VC_SEND_BUFFER_SIZE
#define VC_SEND_BUFFER_SIZE (2*1024)
#endif

#ifndef VC_RECV_BUFFER_SIZE
#define VC_RECV_BUFFER_SIZE (4*1024)
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


// Connect to a Veracruz enclave and verify the attestation via its
// certificate chain
int vc_connect(vc_t *vc);

// Disconnect and clean up memory
//
// Note even if an error is returned, memory is still cleaned up
//
int vc_close(vc_t *vc);

// Send data to a Veracruz instance
int vc_send_data(vc_t *vc,
        const char *name,
        const uint8_t *data,
        size_t data_len);



#endif
