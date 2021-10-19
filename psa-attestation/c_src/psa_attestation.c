/*
 * Copyright (c) 2018-2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "psa/initial_attestation.h"
#include "attestation.h"
#include "psa/crypto.h"

void attest_core_set_key_handle(psa_key_handle_t new_key_handle);

#define IOVEC_LEN(x) (sizeof(x)/sizeof(x[0]))

psa_status_t
psa_initial_attest_load_key(uint8_t const *private_key,
                            size_t private_key_size,
                            uint16_t *p_key_handle) {
    psa_status_t status;
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    psa_key_attributes_t attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH );
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1));
    status = psa_import_key(&attributes,
                            private_key,
                            private_key_size,
                            p_key_handle);
    if (status != PSA_SUCCESS) {
        return status;
    }
    attest_core_set_key_handle(*p_key_handle);

    return PSA_SUCCESS;
}

psa_status_t
psa_initial_attest_remove_key(uint16_t key_handle) {
    psa_status_t status;
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_destroy_key(key_handle);
    return status;
}

psa_status_t
psa_initial_attest_get_token(const uint8_t *fw_hash,
                             size_t         fw_hash_size,
                             const uint8_t *cert_hash,
                             size_t         cert_hash_size,
                             const char    *enclave_name,
                             size_t         enclave_name_size,
                             const uint8_t *auth_challenge,
                             size_t         challenge_size,
                             uint8_t       *token_buf,
                             size_t         token_buf_size,
                             size_t        *token_size)
{
    return initial_attest_get_token(fw_hash,
                                    fw_hash_size,
                                    cert_hash,
                                    cert_hash_size,
                                    enclave_name,
                                    enclave_name_size,
                                    auth_challenge,
                                    challenge_size,
                                    token_buf,
                                    token_buf_size,
                                    token_size);
}

psa_status_t
psa_initial_attest_get_token_size(size_t fw_hash_size,
                                  size_t cert_hash_size,
                                  size_t enclave_name_size,
                                  size_t  challenge_size,
                                  size_t *token_size)
{
    return initial_attest_get_token_size(fw_hash_size,
                                         cert_hash_size,
                                         enclave_name_size,
                                         challenge_size,
                                         token_size);
}
