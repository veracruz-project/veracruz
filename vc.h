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

#ifndef VC_SEND_BUFFER_SIZE
#define VC_SEND_BUFFER_SIZE (4*1024)
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

    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;

    // buffers for shuffling TLS data around
    uint8_t *send_buf;
    uint8_t *recv_buf;
} vc_t;

// Attest and connect to a Veracruz enclave
int vc_attest_and_connect(vc_t *vc);

// Disconnect and clean up memory
//
// Note even if an error is returned, memory is still cleaned up
//
int vc_close(vc_t *vc);

// Attest the Veracruz enclave
//
// Note, this does a single standalone attestation without establishing
// a connection to the attested enclave, you likely want vc_attest_and_connect
// if further operations are wanted
//
int vc_attest(
        char *enclave_name, size_t enclave_name_len,
        uint8_t *enclave_cert_hash, size_t *enclave_cert_hash_len);

// Connect to an attested Veracruz enclave
//
// Note, this assumes the enclave has already been attested, you likely want
// to use vc_attest_and_connect, which ensures the enclave is attested when
// the connection is established 
int vc_connect(vc_t *vc,
        const char *enclave_name,
        const uint8_t *enclave_cert_hash, size_t enclave_cert_hash_len);

#endif
