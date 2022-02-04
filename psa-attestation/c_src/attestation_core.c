/*
 * Copyright (c) 2018-2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include "psa/initial_attestation.h" // for psa_status_t
#include "mbedtls/sha256.h"
#include "psa/error.h" // for PSA_SUCCESS
#include "attestation.h"

//#include "attestation_key.h"
#include "tfm_boot_status.h"
//#include "tfm_plat_defs.h"
#include "tfm_plat_device_id.h"
#include "tfm_plat_boot_seed.h"
#include "tfm_attest_hal.h"
#include "attest_token.h"
#include "attest_eat_defines.h"
#include "t_cose_common.h"
#include "tfm_memory_utils.h"
//#include "platform/include/tfm_plat_crypto_keys.h"

#define MAX_BOOT_STATUS 512

/* Indicates how to encode SW components' measurements in the CBOR map */
#define EAT_SW_COMPONENT_NESTED     1  /* Nested map */
#define EAT_SW_COMPONENT_NOT_NESTED 0  /* Flat structure */

/*!
 * \struct attest_boot_data
 *
 * \brief Contains the received boot status information from bootloader
 *
 * \details This is a redefinition of \ref tfm_boot_data to allocate the
 *          appropriate, service dependent size of \ref boot_data.
 */
 #if 1
struct attest_boot_data {
    struct shared_data_tlv_header header;
    uint8_t data[MAX_BOOT_STATUS];
};
#endif
/*!
 * \var boot_data
 *
 * \brief Store the boot status in service's memory.
 *
 * \details Boot status comes from the secure bootloader and primarily stored
 *          on a memory area which is shared between bootloader and SPM.
 *          SPM provides the \ref tfm_core_get_boot_data() API to retrieve
 *          the service related data from shared area.
 */
 #if 1
__attribute__ ((aligned(4)))
static struct attest_boot_data boot_data;
#endif

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
        return PSA_ERROR_SERVICE_FAILURE;
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

/*!
 * \brief Static function to convert a pointer and size info to unsigned
 *        integer number. Max 32bits unsigned integers are supported.
 *
 * This implementation assumes that the endianness of the sender and receiver
 * of the data is the same because they are actually running on the same CPU
 * instance. If this assumption is not true than this function must be
 * refactored accordingly.
 *
 * \param[in]  int_ptr  Pointer to the unsigned integer
 * \param[in]  len      Size of the unsigned integers in bytes
 * \param[in]  value    Pointer where to store the converted value
 *
 * \return Returns 0 on success and -1 on error.
 */
 #if 0
static inline int32_t get_uint(const void *int_ptr,
                               size_t len,
                               uint32_t *value)
{
    uint16_t uint16;

    switch (len) {
    case 1:
        *value = (uint32_t)(*(uint8_t  *)(int_ptr));
        break;
    case 2:
        /* Avoid unaligned access */
        (void)tfm_memcpy(&uint16, int_ptr, sizeof(uint16));
        *value = (uint32_t)uint16;
        break;
    case 4:
        /* Avoid unaligned access */
        (void)tfm_memcpy(value, int_ptr, sizeof(uint32_t));
        break;
    default:
        return -1;
    }

    return 0;
}
#endif

/*!
 * \brief Static function to look up all entires in the shared data area
 *       (boot status) which belong to a specific module.
 *
 * \param[in]     module  The identifier of SW module to look up based on this
 * \param[out]    claim   The type of SW module's attribute
 * \param[out]    tlv_len Length of the shared data entry
 * \param[in/out] tlv_ptr Pointer to the shared data entry. If its value NULL as
 *                        input then it will starts the look up from the
 *                        beginning of the shared data section. If not NULL then
 *                        it continue look up from the next entry. It returns
 *                        the address of next found entry which belongs to
 *                        module.
 *
 * \retval    -1          Error, boot status is malformed
 * \retval     0          Entry not found
 * \retval     1          Entry found
 */
static int32_t attest_get_tlv_by_module(uint8_t    module,
                                        uint8_t   *claim,
                                        uint16_t  *tlv_len,
                                        uint8_t  **tlv_ptr)
{
    struct shared_data_tlv_entry tlv_entry;
    uint8_t *tlv_end;
    uint8_t *tlv_curr;

    if (boot_data.header.tlv_magic != SHARED_DATA_TLV_INFO_MAGIC) {
        return -1;
    }

    /* Get the boundaries of TLV section where to lookup*/
    tlv_end = (uint8_t *)&boot_data + boot_data.header.tlv_tot_len;
    if (*tlv_ptr == NULL) {
        /* At first call set to the beginning of the TLV section */
        tlv_curr = boot_data.data;
    } else {
        /* Any subsequent call set to the next TLV entry */
        (void)tfm_memcpy(&tlv_entry, *tlv_ptr, SHARED_DATA_ENTRY_HEADER_SIZE);
        tlv_curr  = (*tlv_ptr) + tlv_entry.tlv_len;
    }

    /* Iterates over the TLV section and returns the address and size of TLVs
     * with requested module identifier
     */
    for (; tlv_curr < tlv_end; tlv_curr += tlv_entry.tlv_len) {
        /* Create local copy to avoid unaligned access */
        (void)tfm_memcpy(&tlv_entry, tlv_curr, SHARED_DATA_ENTRY_HEADER_SIZE);
        if (GET_IAS_MODULE(tlv_entry.tlv_type) == module) {
            *claim   = GET_IAS_CLAIM(tlv_entry.tlv_type);
            *tlv_ptr = tlv_curr;
            *tlv_len = tlv_entry.tlv_len;
            return 1;
        }
    }

    return 0;
}

/*!
 * \brief Static function to look up specific claim belongs to SW_GENERAL module
 *
 * \param[in]   claim    The claim ID to look for
 * \param[out]  tlv_len  Length of the shared data entry
 * \param[out]  tlv_ptr  Pointer to a shared data entry which belongs to the
 *                       SW_GENERAL module.
 *
 * \retval    -1          Error, boot status is malformed
 * \retval     0          Entry not found
 * \retval     1          Entry found
 */
static int32_t attest_get_tlv_by_id(uint8_t    claim,
                                    uint16_t  *tlv_len,
                                    uint8_t  **tlv_ptr)
{
    uint8_t tlv_id;
    uint8_t module = SW_GENERAL;
    int32_t found;

    /* Ensure that look up starting from the beginning of the boot status */
    *tlv_ptr = NULL;

    /* Look up specific TLV entry which belongs to SW_GENERAL module */
    do {
        /* Look up next entry */
        found = attest_get_tlv_by_module(module, &tlv_id,
                                         tlv_len, tlv_ptr);
        if (found != 1) {
            break;
        }
        /* At least one entry was found which belongs to SW_GENERAL,
         * check whether this one is looked for
         */
        if (claim == tlv_id) {
            break;
        }
    } while (found == 1);

    return found;
}

#ifdef INDIVIDUAL_SW_COMPONENTS /* DEPRECATED */
/*!
 * \brief Static function to add SW component related claims to attestation
 *        token in CBOR format.
 *
 *  This function translates between TLV  and CBOR encoding.
 *
 * \param[in]  token_ctx    Attestation token encoding context
 * \param[in]  tlv_id       The ID of claim
 * \param[in]  claim_value  A structure which carries a pointer and size about
 *                          the data item to be added to the token
 *
 * \deprecated This function is deprecated and will probably be removed
 *             in the future.
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_sw_component_claim(struct attest_token_ctx *token_ctx,
                              uint8_t tlv_id,
                              const struct q_useful_buf_c *claim_value)
{
    switch (tlv_id) {
    case SW_MEASURE_VALUE:
        attest_token_add_bstr(token_ctx,
                              EAT_CBOR_SW_COMPONENT_MEASUREMENT_VALUE,
                              claim_value);
        break;
    case SW_MEASURE_TYPE:
        attest_token_add_tstr(token_ctx,
                              EAT_CBOR_SW_COMPONENT_MEASUREMENT_DESC,
                              claim_value);
        break;
    case SW_VERSION:
        attest_token_add_tstr(token_ctx,
                              EAT_CBOR_SW_COMPONENT_VERSION,
                              claim_value);
        break;
    case SW_SIGNER_ID:
        attest_token_add_bstr(token_ctx,
                              EAT_CBOR_SW_COMPONENT_SIGNER_ID,
                              claim_value);
        break;
    case SW_TYPE:
        attest_token_add_tstr(token_ctx,
                              EAT_CBOR_SW_COMPONENT_MEASUREMENT_TYPE,
                              claim_value);
        break;
    default:
        return PSA_ATTEST_ERR_GENERAL;
    }

    return PSA_ATTEST_ERR_SUCCESS;
}

/*!
 * \brief Static function to add the measurement data of a single SW components
 *        to the attestation token.
 *
 * \param[in]  token_ctx    Token encoding context
 * \param[in]  module       SW component identifier
 * \param[in]  tlv_address  Address of the first TLV entry in the boot status,
 *                          which belongs to this SW component.
 * \param[in]  nested_map   Flag to indicate that how to encode the SW component
 *                          measurement data: nested map or non-nested map.
 * \deprecated This function is deprecated and will probably be removed
 *             in the future.
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_single_sw_measurment(struct attest_token_ctx *token_ctx,
                                uint8_t module,
                                uint8_t *tlv_address,
                                uint32_t nested_map)
{
    struct shared_data_tlv_entry tlv_entry;
    uint16_t tlv_len;
    uint8_t  tlv_id;
    uint8_t *tlv_ptr = tlv_address;
    int32_t found = 1;
    struct q_useful_buf_c claim_value;
    enum psa_attest_err_t res;
    QCBOREncodeContext *cbor_encode_ctx;

    /* Create local copy to avoid unaligned access */
    (void)tfm_memcpy(&tlv_entry, tlv_address, SHARED_DATA_ENTRY_HEADER_SIZE);
    tlv_len = tlv_entry.tlv_len;
    tlv_id = GET_IAS_CLAIM(tlv_entry.tlv_type);

    cbor_encode_ctx = attest_token_borrow_cbor_cntxt(token_ctx);

    /* Open nested map for SW component measurement claims */
    if (nested_map) {
        QCBOREncode_OpenMapInMapN(cbor_encode_ctx,
                                 EAT_CBOR_SW_COMPONENT_MEASUREMENT_VALUE);
    }

    /* Look up all measurement TLV entry which belongs to the SW component */
    while (found) {
        /* Here only measurement claims are added to the token */
        if (GET_IAS_MEASUREMENT_CLAIM(tlv_id)) {
            claim_value.ptr = tlv_ptr + SHARED_DATA_ENTRY_HEADER_SIZE;
            claim_value.len = tlv_len - SHARED_DATA_ENTRY_HEADER_SIZE;
            res = attest_add_sw_component_claim(token_ctx,
                                                tlv_id,
                                                &claim_value);
            if (res != PSA_ATTEST_ERR_SUCCESS) {
                return res;
            }
        }

        /* Look up next entry it can be non-measurement claim*/
        found = attest_get_tlv_by_module(module, &tlv_id,
                                         &tlv_len, &tlv_ptr);
        if (found == -1) {
            return PSA_ATTEST_ERR_CLAIM_UNAVAILABLE;
        }
    }

    if (nested_map) {
        QCBOREncode_CloseMap(cbor_encode_ctx);
    }

    return PSA_ATTEST_ERR_SUCCESS;
}

/*!
 * \brief Static function to add the claims of a single SW components to the
 *        attestation token.
 *
 * \param[in]  token_ctx    Token encoding context
 * \param[in]  module       SW component identifier
 * \param[in]  tlv_address  Address of the first TLV entry in the boot status,
 *                          which belongs to this SW component.
 *
 * \deprecated This function is deprecated and will probably be removed
 *             in the future.
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_single_sw_component(struct attest_token_ctx *token_ctx,
                               uint8_t module,
                               uint8_t *tlv_address)
{
    struct shared_data_tlv_entry tlv_entry;
    uint16_t tlv_len;
    uint8_t  tlv_id;
    uint8_t *tlv_ptr = tlv_address;
    int32_t found = 1;
    uint32_t measurement_claim_cnt = 0;
    struct q_useful_buf_c claim_value;
    QCBOREncodeContext *cbor_encode_ctx;
    enum psa_attest_err_t res;

    /* Create local copy to avoid unaligned access */
    (void)tfm_memcpy(&tlv_entry, tlv_address, SHARED_DATA_ENTRY_HEADER_SIZE);
    tlv_len = tlv_entry.tlv_len;
    tlv_id = GET_IAS_CLAIM(tlv_entry.tlv_type);

    /* Open map which stores claims belong to a SW component */
    cbor_encode_ctx = attest_token_borrow_cbor_cntxt(token_ctx);
    QCBOREncode_OpenMap(cbor_encode_ctx);

    /* Look up all TLV entry which belongs to the same SW component */
    while (found) {
        /* Check whether claim is measurement claim */
        if (GET_IAS_MEASUREMENT_CLAIM(tlv_id)) {
            if (measurement_claim_cnt == 0) {
                /* Call only once when first measurement claim found */
                measurement_claim_cnt++;
                res = attest_add_single_sw_measurment(
                                                   token_ctx,
                                                   module,
                                                   tlv_ptr,
                                                   EAT_SW_COMPONENT_NOT_NESTED);
                if (res != PSA_ATTEST_ERR_SUCCESS) {
                    return res;
                }
            }
        } else {
            /* Adding top level claims */
            claim_value.ptr = tlv_ptr + SHARED_DATA_ENTRY_HEADER_SIZE;
            claim_value.len = tlv_len - SHARED_DATA_ENTRY_HEADER_SIZE;
            res = attest_add_sw_component_claim(token_ctx,
                                                tlv_id,
                                                &claim_value);
            if (res != PSA_ATTEST_ERR_SUCCESS) {
                return res;
            }
        }

        /* Look up next entry which belongs to SW component */
        found = attest_get_tlv_by_module(module, &tlv_id,
                                         &tlv_len, &tlv_ptr);
        if (found == -1) {
            return PSA_ATTEST_ERR_CLAIM_UNAVAILABLE;
        }
    }

    /* Close map which stores claims belong to a SW component */
    QCBOREncode_CloseMap(cbor_encode_ctx);

    return PSA_ATTEST_ERR_SUCCESS;
}
#endif /* INDIVIDUAL_SW_COMPONENTS */

/*!
 * \brief Static function to add the claims of all SW components to the
 *        attestation token.
 *
 * \param[in]  token_ctx  Token encoding context
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_all_sw_components(struct attest_token_ctx *token_ctx)
{
    uint16_t tlv_len;
    uint8_t *tlv_ptr;
    uint8_t  tlv_id;
    int32_t found;
    uint32_t cnt = 0;
    uint8_t module;
    QCBOREncodeContext *cbor_encode_ctx = NULL;
#ifdef INDIVIDUAL_SW_COMPONENTS
    enum psa_attest_err_t res;
#else
    UsefulBufC encoded = NULLUsefulBufC;
#endif

    cbor_encode_ctx = attest_token_borrow_cbor_cntxt(token_ctx);

    /* Starting from module 1, because module 0 contains general claims which
     * are not related to SW module(i.e: boot_seed, etc.)
     */
    for (module = 1; module < SW_MAX; ++module) {
        /* Indicates to restart the look up from the beginning of the shared
         * data section
         */
        tlv_ptr = NULL;

        /* Look up the first TLV entry which belongs to the SW module */
        found = attest_get_tlv_by_module(module, &tlv_id,
                                         &tlv_len, &tlv_ptr);
        if (found == -1) {
            return PSA_ATTEST_ERR_CLAIM_UNAVAILABLE;
        }

        if (found == 1) {
            cnt++;
            if (cnt == 1) {
                /* Open array which stores SW components claims */
                QCBOREncode_OpenArrayInMapN(cbor_encode_ctx,
                                            EAT_CBOR_ARM_LABEL_SW_COMPONENTS);
            }

#ifdef INDIVIDUAL_SW_COMPONENTS
            res = attest_add_single_sw_component(token_ctx, module, tlv_ptr);
            if (res != PSA_ATTEST_ERR_SUCCESS) {
                return res;
            }
#else
            encoded.ptr = tlv_ptr + SHARED_DATA_ENTRY_HEADER_SIZE;
            encoded.len = tlv_len - SHARED_DATA_ENTRY_HEADER_SIZE;
            QCBOREncode_AddEncoded(cbor_encode_ctx, encoded);
#endif /* INDIVIDUAL_SW_COMPONENTS */
        }
    }

    if (cnt != 0) {
        /* Close array which stores SW components claims*/
        QCBOREncode_CloseArray(cbor_encode_ctx);
    } else {
        /* If there is not any SW components' measurement in the boot status
         * then include this claim to indicate that this state is intentional
         */
        attest_token_add_integer(token_ctx,
                                 EAT_CBOR_ARM_LABEL_NO_SW_COMPONENTS,
                                 (int64_t)NO_SW_COMPONENT_FIXED_VALUE);
    }

    return PSA_ATTEST_ERR_SUCCESS;
}

/*!
 * \brief Static function to add boot seed claim to attestation token.
 *
 * \param[in]  token_ctx  Token encoding context
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
// static enum psa_attest_err_t
// attest_add_boot_seed_claim(struct attest_token_ctx *token_ctx)
// {
//     uint8_t boot_seed[BOOT_SEED_SIZE];
//     enum tfm_plat_err_t res;
//     struct q_useful_buf_c claim_value = {0};
//     uint16_t tlv_len;
//     uint8_t *tlv_ptr = NULL;
//     int32_t found = 0;

//     /* First look up BOOT_SEED in boot status, it might comes from bootloader */
//     found = attest_get_tlv_by_id(BOOT_SEED, &tlv_len, &tlv_ptr);
//     if (found == 1) {
//         claim_value.ptr = tlv_ptr + SHARED_DATA_ENTRY_HEADER_SIZE;
//         claim_value.len = tlv_len - SHARED_DATA_ENTRY_HEADER_SIZE;
//     } else {
//         /* If not found in boot status then use callback function to get it
//          * from runtime SW
//          */
//         res = tfm_plat_get_boot_seed(sizeof(boot_seed), boot_seed);
//         if (res != TFM_PLAT_ERR_SUCCESS) {
//             return PSA_ATTEST_ERR_CLAIM_UNAVAILABLE;
//         }
//         claim_value.ptr = boot_seed;
//         claim_value.len = BOOT_SEED_SIZE;
//     }

//     attest_token_add_bstr(token_ctx,
//                           EAT_CBOR_ARM_LABEL_BOOT_SEED,
//                           &claim_value);

//     return PSA_ATTEST_ERR_SUCCESS;
// }

/*!
 * \brief Static function to add instance id claim to attestation token.
 *
 * \param[in]  token_ctx  Token encoding context
 *
 * \note This mandatory claim represents the unique identifier of the instance.
 *       In the PSA definition it is a hash of the public attestation key of the
 *       instance. The claim will be represented by the EAT standard claim UEID
 *       of type GUID. The EAT definition of a GUID type is that it will be
 *       between 128 & 256 bits but this implementation will use the full 256
 *       bits to accommodate a hash result.
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_instance_id_claim(struct attest_token_ctx *token_ctx)
{
    psa_status_t crypto_res;
    enum psa_attest_err_t attest_res;
    uint8_t instance_id[INSTANCE_ID_MAX_SIZE];
    size_t instance_id_len;
    struct q_useful_buf_c claim_value;
    uint8_t *public_key;
    size_t key_len;
    //psa_ecc_curve_t psa_curve;
    //psa_hash_operation_t hash = psa_hash_operation_init();

#if 0
    attest_res = attest_get_initial_attestation_public_key(&public_key,
                                                           &key_len,
                                                           &psa_curve);
    if (attest_res != PSA_ATTEST_ERR_SUCCESS) {
        return PSA_ATTEST_ERR_CLAIM_UNAVAILABLE;
    }
#endif

    mbedtls_sha256_context hash_context;
    mbedtls_sha256_init( &hash_context );

    crypto_res = mbedtls_sha256_update( &hash_context,
                               public_key,
                              key_len );
    if (crypto_res != 0) {
        return PSA_ATTEST_ERR_CLAIM_UNAVAILABLE;
    }

    /* The hash starts from the second byte, leaving the first free. */
    crypto_res = mbedtls_sha256_finish(&hash_context, instance_id + 1);
    if (crypto_res != 0) {
        return PSA_ATTEST_ERR_CLAIM_UNAVAILABLE;
    }
    instance_id_len = 32;

    /* First byte indicates the type: 0x01 indicates GUID */
    instance_id[0] = 0x01;
    instance_id_len += 1;

    claim_value.ptr = instance_id;
    claim_value.len = instance_id_len;
    attest_token_add_bstr(token_ctx,
                          EAT_CBOR_ARM_LABEL_UEID,
                          &claim_value);

    return PSA_ATTEST_ERR_SUCCESS;
}

/*!
 * \brief Static function to add implementation id claim to attestation token.
 *
 * \param[in]  token_ctx  Token encoding context
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
// static enum psa_attest_err_t
// attest_add_implementation_id_claim(struct attest_token_ctx *token_ctx)
// {
//     uint8_t implementation_id[IMPLEMENTATION_ID_MAX_SIZE];
//     enum tfm_plat_err_t res_plat;
//     uint32_t size = sizeof(implementation_id);
//     struct q_useful_buf_c claim_value;

//     res_plat = tfm_plat_get_implementation_id(&size, implementation_id);
//     if (res_plat != TFM_PLAT_ERR_SUCCESS) {
//         return PSA_ATTEST_ERR_CLAIM_UNAVAILABLE;
//     }

//     claim_value.ptr = implementation_id;
//     claim_value.len  = size;
//     attest_token_add_bstr(token_ctx,
//                           EAT_CBOR_ARM_LABEL_IMPLEMENTATION_ID,
//                           &claim_value);

//     return PSA_ATTEST_ERR_SUCCESS;
// }

/*!
 * \brief Static function to add caller id claim to attestation token.
 *
 * \param[in]  token_ctx  Token encoding context
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_caller_id_claim(struct attest_token_ctx *token_ctx)
{
    enum psa_attest_err_t res;
    int32_t caller_id;

#if 0
    res = attest_get_caller_client_id(&caller_id);
    if (res != PSA_ATTEST_ERR_SUCCESS) {
        return res;
    }
#endif

    attest_token_add_integer(token_ctx,
                             EAT_CBOR_ARM_LABEL_CLIENT_ID,
                             (int64_t)caller_id);

    return PSA_ATTEST_ERR_SUCCESS;
}

/*!
 * \brief Static function to add security lifecycle claim to attestation token.
 *
 * \param[in]  token_ctx  Token encoding context
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
// static enum psa_attest_err_t
// attest_add_security_lifecycle_claim(struct attest_token_ctx *token_ctx)
// {
//     enum tfm_security_lifecycle_t security_lifecycle;
//     uint32_t slc_value;
//     int32_t res;
//     struct q_useful_buf_c claim_value = {0};
//     uint16_t tlv_len;
//     uint8_t *tlv_ptr = NULL;
//     int32_t found = 0;

//     /* First look up lifecycle state in boot status, it might comes
//      * from bootloader
//      */
//     found = attest_get_tlv_by_id(SECURITY_LIFECYCLE, &tlv_len, &tlv_ptr);
//     if (found == 1) {
//         claim_value.ptr = tlv_ptr + SHARED_DATA_ENTRY_HEADER_SIZE;
//         claim_value.len = tlv_len - SHARED_DATA_ENTRY_HEADER_SIZE;
//         #if 0
//         res = get_uint(claim_value.ptr, claim_value.len, &slc_value);
//         #endif
//         if (res) {
//             return PSA_ATTEST_ERR_GENERAL;
//         }
//         security_lifecycle = (enum tfm_security_lifecycle_t)slc_value;
//     } else {
//         /* If not found in boot status then use callback function to get it
//          * from runtime SW
//          */
//         security_lifecycle = tfm_attest_hal_get_security_lifecycle();
//     }

//     /* Sanity check */
//     if (security_lifecycle > TFM_SLC_DECOMMISSIONED) {
//         return PSA_ATTEST_ERR_GENERAL;
//     }

//     attest_token_add_integer(token_ctx,
//                              EAT_CBOR_ARM_LABEL_SECURITY_LIFECYCLE,
//                              (int64_t)security_lifecycle);

//     return PSA_ATTEST_ERR_SUCCESS;
// }

/*!
 * \brief Static function to add challenge claim to attestation token.
 *
 * \param[in]  token_ctx  Token encoding context
 * \param[in]  challenge  Pointer to buffer which stores the challenge
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_challenge_claim(struct attest_token_ctx   *token_ctx,
                           const struct q_useful_buf_c *challenge)
{
    attest_token_add_bstr(token_ctx, EAT_CBOR_ARM_LABEL_CHALLENGE, challenge);

    return PSA_ATTEST_ERR_SUCCESS;
}

#ifdef INCLUDE_OPTIONAL_CLAIMS /* Remove them from release build */
/*!
 * \brief Static function to add the verification service indicator claim
 *        to the attestation token.
 *
 * \param[in]  token_ctx  Token encoding context
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_verification_service(struct attest_token_ctx *token_ctx)
{
    struct q_useful_buf_c service;
    uint32_t size;

    service.ptr = tfm_attest_hal_get_verification_service(&size);

    if (service.ptr) {
        service.len = size;
        attest_token_add_tstr(token_ctx,
                              EAT_CBOR_ARM_LABEL_ORIGINATION,
                              &service);
    }

    return PSA_ATTEST_ERR_SUCCESS;
}

/*!
 * \brief Static function to add the name of the profile definition document
 *
 * \param[in]  token_ctx  Token encoding context
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_profile_definition(struct attest_token_ctx *token_ctx)
{
    struct q_useful_buf_c profile;
    uint32_t size;

    profile.ptr = tfm_attest_hal_get_profile_definition(&size);

    if (profile.ptr) {
        profile.len = size;
        attest_token_add_tstr(token_ctx,
                              EAT_CBOR_ARM_LABEL_PROFILE_DEFINITION,
                              &profile);
    }

    return PSA_ATTEST_ERR_SUCCESS;
}

/*!
 * \brief Static function to add hardware version claim to attestation token.
 *
 * \param[in]  token_ctx  Token encoding context
 *
 * \return Returns error code as specified in \ref psa_attest_err_t
 */
static enum psa_attest_err_t
attest_add_hw_version_claim(struct attest_token_ctx *token_ctx)
{
    uint8_t hw_version[HW_VERSION_MAX_SIZE];
    enum tfm_plat_err_t res_plat;
    uint32_t size = sizeof(hw_version);
    struct q_useful_buf_c claim_value = {0};
    uint16_t tlv_len;
    uint8_t *tlv_ptr = NULL;
    int32_t found = 0;

    /* First look up HW version in boot status, it might comes
     * from bootloader
     */
    found = attest_get_tlv_by_id(HW_VERSION, &tlv_len, &tlv_ptr);
    if (found == 1) {
        claim_value.ptr = tlv_ptr + SHARED_DATA_ENTRY_HEADER_SIZE;
        claim_value.len = tlv_len - SHARED_DATA_ENTRY_HEADER_SIZE;
    } else {
        /* If not found in boot status then use callback function to get it
         * from runtime SW
         */
        res_plat = tfm_plat_get_hw_version(&size, hw_version);
        if (res_plat != TFM_PLAT_ERR_SUCCESS) {
            return PSA_ATTEST_ERR_CLAIM_UNAVAILABLE;
        }
        claim_value.ptr = hw_version;
        claim_value.len = size;
    }

    attest_token_add_tstr(token_ctx,
                          EAT_CBOR_ARM_LABEL_HW_VERSION,
                          &claim_value);

    return PSA_ATTEST_ERR_SUCCESS;
}
#endif /* INCLUDE_OPTIONAL_CLAIMS */

/*!
 * \brief Static function to verify the input challenge size
 *
 *  Only discrete sizes are accepted.
 *
 * \param[in] challenge_size  Size of challenge object in bytes.
 *
 * \retval  PSA_ATTEST_ERR_SUCCESS
 * \retval  PSA_ATTEST_ERR_INVALID_INPUT
 */
static enum psa_attest_err_t attest_verify_challenge_size(size_t challenge_size)
{
    switch (challenge_size) {
    /* Intentional fall through */
    case PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32:
    case PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48:
    case PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64:
        return PSA_ATTEST_ERR_SUCCESS;
    }

    return PSA_ATTEST_ERR_INVALID_INPUT;
}

#ifdef INCLUDE_TEST_CODE /* Remove them from release build */
/*!
 * \brief Static function to get the option flags from challenge object
 *
 * Option flags are passed in if the challenge is 64 bytes long and the last
 * 60 bytes are all 0. In this case the first 4 bytes of the challenge is
 * the option flags for test.
 *
 * See flag definition in attest_token.h
 *
 * \param[in]  challenge     Structure to carry the challenge value:
 *                           pointer + challeng's length.
 * \param[out] option_flags  Flags to select different custom options,
 *                           for example \ref TOKEN_OPT_OMIT_CLAIMS.
 * \param[out] key_select    Selects which attestation key to sign with.
 */
static void attest_get_option_flags(struct q_useful_buf_c *challenge,
                                    uint32_t *option_flags,
                                    int32_t  *key_select)
{
    uint32_t found_option_flags = 1;
    uint32_t option_flags_size = sizeof(uint32_t);
    uint8_t *challenge_end;
    uint8_t *challenge_data;

    /* Get option flags if there is encoded in the challenge object */
    if ((challenge->len == PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64) &&
        (challenge->ptr)) {
        challenge_end  = ((uint8_t *)challenge->ptr) + challenge->len;
        challenge_data = ((uint8_t *)challenge->ptr) + option_flags_size;

        /* Compare bytes(4-63) with 0 */
        while (challenge_data < challenge_end) {
            if (*challenge_data++ != 0) {
                found_option_flags = 0;
                break;
            }
        }
    } else {
        found_option_flags = 0;
    }

    if (found_option_flags) {
        (void)tfm_memcpy(option_flags, challenge->ptr, option_flags_size);

        /* Lower three bits are the key select */
        *key_select = *option_flags & 0x7;
    } else {
        *option_flags = 0;
        *key_select = 0;
    }
}
#endif /* INCLUDE_TEST_CODE */

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
    struct attest_token_ctx attest_token_ctx;
    //psa_key_handle_t key_handle;
    uint32_t option_flags = 0;

#if 0
    attest_err = attest_register_initial_attestation_key();
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }
#endif

#ifdef INCLUDE_TEST_CODE /* Remove them from release build */
    attest_get_option_flags(challenge, &option_flags, &key_select);
#endif
    // TODO: Set up the Private Signing key, assign handle to key_handle


    /* Get started creating the token. This sets up the CBOR and COSE contexts
     * which causes the COSE headers to be constructed.
     */
    token_err = attest_token_start(&attest_token_ctx,
                                   option_flags,            /* option_flags */
                                   key_handle,              /* key_select   */
                                   T_COSE_ALGORITHM_ES256,  /* alg_select   */
                                   token);

    if (token_err != ATTEST_TOKEN_ERR_SUCCESS) {
        attest_err = error_mapping_to_psa_attest_err_t(token_err);
        goto error;
    }

    attest_err = attest_add_challenge_claim(&attest_token_ctx,
                                            challenge);
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }

    attest_token_add_bstr(&attest_token_ctx,
                          EAT_CBOR_ARM_LABEL_SW_COMPONENTS, 
                          fw_hash);

    attest_token_add_bstr(&attest_token_ctx,
                          EAT_CBOR_ARM_LABEL_ORIGINATION,
                          cert_hash);

    attest_token_add_bstr(&attest_token_ctx,
                          EAT_CBOR_ARM_LABEL_CLIENT_ID,
                          enclave_name);

    if (0 && !(option_flags & TOKEN_OPT_OMIT_CLAIMS)) {
        /* Mandatory claims in IAT token */
        // attest_err = attest_add_boot_seed_claim(&attest_token_ctx);
        // if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        //     goto error;
        // }

        attest_err = attest_add_instance_id_claim(&attest_token_ctx);
        if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
            goto error;
        }

        // attest_err = attest_add_implementation_id_claim(&attest_token_ctx);
        // if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        //     goto error;
        // }

        attest_err = attest_add_caller_id_claim(&attest_token_ctx);
        if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
            goto error;
        }

        // attest_err = attest_add_security_lifecycle_claim(&attest_token_ctx);
        // if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        //     goto error;
        // }

        attest_err = attest_add_all_sw_components(&attest_token_ctx);
        if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
            goto error;
        }

#ifdef INCLUDE_OPTIONAL_CLAIMS
        /* Optional claims in IAT token, remove them from release build */
        attest_err = attest_add_verification_service(&attest_token_ctx);
        if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
            goto error;
        }

        attest_err = attest_add_profile_definition(&attest_token_ctx);
        if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
            goto error;
        }

        attest_err = attest_add_hw_version_claim(&attest_token_ctx);
        if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
            goto error;
        }
#endif /* INCLUDE_OPTIONAL_CLAIMS */
    }

    /* Finish up creating the token. This is where the actual signature
     * is generated. This finishes up the CBOR encoding too.
     */
    token_err = attest_token_finish(&attest_token_ctx, completed_token);
    if (token_err) {
        attest_err = error_mapping_to_psa_attest_err_t(token_err);
        goto error;
    }

error:
    if (attest_err == PSA_ATTEST_ERR_SUCCESS) {
        /* We got here normally and therefore care about error codes. */
        #if 0
        attest_err = attest_unregister_initial_attestation_key();
        #endif
    }
    else {
        /* Error handler: just remove they key and preserve error. */
        #if 0
        (void)attest_unregister_initial_attestation_key();
        #endif
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

    attest_err = attest_verify_challenge_size(challenge.len);
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }

    struct q_useful_buf_c fw_hash_buf;
    fw_hash_buf.ptr = fw_hash;
    fw_hash_buf.len = fw_hash_size;

    struct q_useful_buf_c cert_hash_buf;
    cert_hash_buf.ptr = cert_hash;
    cert_hash_buf.len = cert_hash_size;

    struct q_useful_buf_c enclave_name_buf;
    enclave_name_buf.ptr = enclave_name;
    enclave_name_buf.len = enclave_name_size;
#if 0
    attest_err = attest_check_memory_access((void *)challenge.ptr,
                                            challenge.len,
                                            TFM_ATTEST_ACCESS_RO);
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }
#endif

    if (token.len == 0) {
        attest_err = PSA_ATTEST_ERR_INVALID_INPUT;
        goto error;
    }

#if 0
    attest_err = attest_check_memory_access(token.ptr,
                                            token.len,
                                            TFM_ATTEST_ACCESS_RW);
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }
#endif

    attest_err = attest_create_token(&fw_hash_buf, &cert_hash_buf, &enclave_name_buf, &challenge, &token, &completed_token);
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }

//    out_vec[0].base = (void *)completed_token.ptr;
 //   out_vec[0].len  = completed_token.len;
    tfm_memcpy(token_buf, completed_token.ptr, completed_token.len);
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

#if 0
    if (out_vec[0].len < sizeof(uint32_t)) {
        attest_err = PSA_ATTEST_ERR_INVALID_INPUT;
        goto error;
    }
#endif

    attest_err = attest_verify_challenge_size(challenge_size);
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }

    attest_err = attest_create_token(&fw_hash_buf, &cert_hash_buf, &enclave_name_buf, &challenge, &token, &completed_token);
    if (attest_err != PSA_ATTEST_ERR_SUCCESS) {
        goto error;
    }

    *token_size = completed_token.len;

error:
    return error_mapping_to_psa_status_t(attest_err);
}
