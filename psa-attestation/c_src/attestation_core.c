/*
 * Copyright (c) 2018-2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include "psa/crypto.h"
#include "attestation.h"

#include "attest_token.h"
#include "attest_eat_defines.h"
#include "t_cose_common.h"

/*!
 * \brief Static function to map return values between \ref psa_attest_err_t
 *        and \ref psa_status_t
 *
 * \param[in]  attest_err  Attestation error code
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
 #if 1
static inline psa_status_t
error_mapping_to_psa_status_t(enum psa_attest_err_t attest_err)
{
    switch (attest_err) {
    case PSA_ATTEST_ERR_SUCCESS:
        return PSA_SUCCESS;
        break;
    case PSA_ATTEST_ERR_INIT_FAILED:
        return PSA_ERROR_GENERIC_ERROR;
        break;
    case PSA_ATTEST_ERR_BUFFER_OVERFLOW:
        return PSA_ERROR_BUFFER_TOO_SMALL;
        break;
    case PSA_ATTEST_ERR_CLAIM_UNAVAILABLE:
        return PSA_ERROR_GENERIC_ERROR;
        break;
    case PSA_ATTEST_ERR_INVALID_INPUT:
        return PSA_ERROR_INVALID_ARGUMENT;
        break;
    case PSA_ATTEST_ERR_GENERAL:
        return PSA_ERROR_GENERIC_ERROR;
        break;
    default:
        return PSA_ERROR_GENERIC_ERROR;
    }
}
#endif

psa_status_t attest_init(void)
{
    enum psa_attest_err_t res;
#if 0
    res = attest_get_boot_data(TLV_MAJOR_IAS,
                               (struct tfm_boot_data *)&boot_data,
                               MAX_BOOT_STATUS);
#endif

    return error_mapping_to_psa_status_t(res);
}

/*!
 * \brief Static function to map return values between \ref attest_token_err_t
 *        and \ref psa_attest_err_t
 *
 * \param[in]  token_err  Token encoding return value
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static inline enum psa_attest_err_t
error_mapping_to_psa_attest_err_t(enum attest_token_err_t token_err)
{
    switch (token_err) {
    case ATTEST_TOKEN_ERR_SUCCESS:
        return PSA_ATTEST_ERR_SUCCESS;
        break;
    case ATTEST_TOKEN_ERR_TOO_SMALL:
        return PSA_ATTEST_ERR_BUFFER_OVERFLOW;
        break;
    default:
        return PSA_ATTEST_ERR_GENERAL;
    }
}

static psa_key_handle_t key_handle;

void attest_core_set_key_handle(psa_key_handle_t new_key_handle) {
    key_handle = new_key_handle;
}
/*!
 * \brief Static function to create the initial attestation token
 *
 * \param[in]  challenge        Structure to carry the challenge value:
 *                              pointer + challeng's length
 * \param[in]  token            Structure to carry the token info, where to
 *                              create it: pointer + buffer's length
 * \param[out] completed_token  Structure to carry the info about the created
 *                              token: pointer + final token's length
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_create_token(struct q_useful_buf_c *fw_hash,
                    struct q_useful_buf_c *cert_hash,
                    struct q_useful_buf_c *enclave_name,
                    struct q_useful_buf_c *challenge,
                    struct q_useful_buf   *token,
                    struct q_useful_buf_c *completed_token)
{
    enum psa_attest_err_t attest_err = PSA_ATTEST_ERR_SUCCESS;
    enum attest_token_err_t token_err;
    //struct attest_token_ctx attest_token_ctx;
    enum attest_token_err_t token_ret;
    struct attest_token_encode_ctx attestation_token_ctx;
    struct q_useful_buf_c c_token;

    /* Get started creating the token. This sets up the CBOR and COSE
	 * contexts which causes the COSE headers to be constructed.
	 */
	token_ret = attest_token_encode_start(&attestation_token_ctx,
					      0,     /* option_flags */
					      key_handle,     /* key_select */
					      T_COSE_ALGORITHM_ES256,
					      token);
    if (token_ret != ATTEST_TOKEN_ERR_SUCCESS) {
        attest_err = error_mapping_to_psa_attest_err_t(token_err);
        return attest_err;
    }

    /* Add partition ID */
    int64_t partition_id = -0xdeadbeef;
    attest_token_encode_add_integer(&attestation_token_ctx,
                                    CCA_PLAT_PARTITION_ID,
                                    partition_id);

    int64_t security_lifecycle = 16384;
    attest_token_encode_add_integer(&attestation_token_ctx,
                                    CCA_PLAT_SECURITY_LIFECYCLE,
                                    security_lifecycle);

    const uint8_t BOOT_SEED_VALUE[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    struct q_useful_buf_c boot_seed;
    boot_seed.ptr = BOOT_SEED_VALUE;
    boot_seed.len = sizeof(BOOT_SEED_VALUE);
    attest_token_encode_add_bstr(&attestation_token_ctx,
                                 CCA_PLAT_BOOT_SEED,
                                 &boot_seed);

    /* Add challenge value, which is the only input from the caller. */
	attest_token_encode_add_bstr(&attestation_token_ctx,
				     CCA_REALM_CHALLENGE,
				     challenge);

	attest_token_encode_add_bstr(&attestation_token_ctx,
				     CCA_REALM_IDENTITY,
				     enclave_name);

	bool debug = true;
	attest_token_encode_add_bool(&attestation_token_ctx,
				     CCA_REALM_DEBUG,
				     debug);

    #define IMPLEMENTATION_ID_MAX_SIZE (32u)
    const uint8_t IMPLEMENTATION_ID[IMPLEMENTATION_ID_MAX_SIZE]= {
        0x61, 0x63, 0x6d, 0x65, 0x2d, 0x69, 0x6d, 0x70,
        0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x74,
        0x69, 0x6f, 0x6e, 0x2d, 0x69, 0x64, 0x2d, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
    };
    struct q_useful_buf_c implementation_id;
    implementation_id.ptr = IMPLEMENTATION_ID;
    implementation_id.len = sizeof(IMPLEMENTATION_ID);
    attest_token_encode_add_bstr(&attestation_token_ctx,
                      CCA_PLAT_IMPLEMENTATION_ID,
                      &implementation_id);

	attest_token_encode_add_integer(&attestation_token_ctx,
					CCA_REALM_HASH_ALGM_ID,
					REALM_MEASUREMENT_ALGO_SHA256);

    attest_token_encode_add_bstr(&attestation_token_ctx,
                                 CCA_PLAT_NONCE,
                                 challenge);
    
    attest_token_encode_add_bstr(&attestation_token_ctx,
                                 CCA_PLAT_INSTANCE_ID,
                                 enclave_name);

    QCBOREncode_OpenArrayInMapN(&attestation_token_ctx.cbor_enc_ctx, CCA_PLAT_SW_COMPONENTS);
        QCBOREncode_OpenMap(&attestation_token_ctx.cbor_enc_ctx);
            QCBOREncode_AddBytesToMapN(&attestation_token_ctx.cbor_enc_ctx,
                                        CCA_SW_COMP_MEASUREMENT_VALUE,
                                        *fw_hash);
            //attest_token_encode_add_bstr(&attestation_token_ctx, CCA_SW_COMP_MEASUREMENT_VALUE, fw_hash);
            char MEASUREMENT_TYPE[5] = "ARoT";
            struct q_useful_buf_c measurement_type;
            measurement_type.ptr = MEASUREMENT_TYPE;
            measurement_type.len = 4;
            QCBOREncode_AddTextToMapN(&attestation_token_ctx.cbor_enc_ctx,
                                        CCA_SW_COMP_MEASUREMENT_TYPE,
                                        measurement_type);

            QCBOREncode_AddBytesToMapN(&attestation_token_ctx.cbor_enc_ctx,
                                    CCA_SW_COMP_SIGNER_ID,
                                    *cert_hash);
    
        QCBOREncode_CloseMap(&attestation_token_ctx.cbor_enc_ctx);
    QCBOREncode_CloseArray(&attestation_token_ctx.cbor_enc_ctx);
	
    attest_token_encode_close_map(&attestation_token_ctx);

    /* Finish up creating the token. This is where the actual signature
    * is generated. This finishes up the CBOR encoding too.
    */
	token_ret = attest_token_encode_finish(
				&attestation_token_ctx,
				completed_token);

    if (token_ret != ATTEST_TOKEN_ERR_SUCCESS) {
        attest_err = error_mapping_to_psa_attest_err_t(token_err);
        return attest_err;
    }
    return attest_err;
}

psa_status_t
initial_attest_get_token(const uint8_t *fw_hash,
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
    enum psa_attest_err_t attest_err = PSA_ATTEST_ERR_SUCCESS;
    struct q_useful_buf_c challenge;
    struct q_useful_buf token;
    struct q_useful_buf_c completed_token;

    challenge.ptr = auth_challenge;
    challenge.len = challenge_size;
    token.ptr = token_buf;
    token.len = token_buf_size;

    struct q_useful_buf_c fw_hash_buf;
    fw_hash_buf.ptr = fw_hash;
    fw_hash_buf.len = fw_hash_size;

    struct q_useful_buf_c cert_hash_buf;
    cert_hash_buf.ptr = cert_hash;
    cert_hash_buf.len = cert_hash_size;

    struct q_useful_buf_c enclave_name_buf;
    enclave_name_buf.ptr = enclave_name;
    enclave_name_buf.len = enclave_name_size;

    if (token.len == 0) {
        attest_err = PSA_ATTEST_ERR_INVALID_INPUT;
        goto error;
    }

    attest_err = attest_create_token(&fw_hash_buf, &cert_hash_buf, &enclave_name_buf, &challenge, &token, &completed_token);
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }

    memcpy(token_buf, completed_token.ptr, completed_token.len);
    *token_size = completed_token.len;

error:
    return error_mapping_to_psa_status_t(attest_err);
}

psa_status_t
initial_attest_get_token_size(size_t fw_hash_size,
                              size_t cert_hash_size,
                              size_t enclave_name_size,
                              size_t  challenge_size,
                              size_t *token_size)
{
    enum psa_attest_err_t attest_err = PSA_ATTEST_ERR_SUCCESS;

    struct q_useful_buf_c challenge;
    struct q_useful_buf token;
    struct q_useful_buf_c completed_token;

    /* Only the size of the challenge is needed */
    challenge.ptr = NULL;
    challenge.len = challenge_size;

    struct q_useful_buf_c fw_hash_buf;
    fw_hash_buf.ptr = NULL;
    fw_hash_buf.len = fw_hash_size;

    struct q_useful_buf_c cert_hash_buf;
    cert_hash_buf.ptr = NULL;
    cert_hash_buf.len = cert_hash_size;

    struct q_useful_buf_c enclave_name_buf;
    enclave_name_buf.ptr = NULL;
    enclave_name_buf.len = enclave_name_size;
    /* Special value to get the size of the token, but token is not created */
    token.ptr = NULL;
    token.len = INT32_MAX;

    attest_err = attest_create_token(&fw_hash_buf, &cert_hash_buf, &enclave_name_buf, &challenge, &token, &completed_token);
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }

    *token_size = completed_token.len;

error:
    return error_mapping_to_psa_status_t(attest_err);
}
