/*
 * (C) COPYRIGHT 2021 ARM Limited or its affiliates.
 * ALL RIGHTS RESERVED
 */

#ifndef __ATTEST_KEY_H__
#define __ATTEST_KEY_H__

#include <mbedtls/ecdsa.h>
#include "t_cose/q_useful_buf.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Register the attestation private key to crypto lib. Loads
 *        the public key if the key has not already been loaded.
 *
 * \retval  0  Key was successfully created.
 * \retval  1  Key creation failed.
 */
unsigned int
attest_create_realm_attestation_key(void);

/**
 * \brief Get a pointer to the keypair for signing realm attestation token.
 *
 * \param[out]  keypair  The pointer to the keypair for signing token.
 */
void
attest_get_realm_signing_key(const mbedtls_ecp_keypair **keypair);

/**
 * \brief Get the hash of the realm attestation public key. The public key hash
 *        is the challenge value in the platform attestation token.
 *
 * \param public_key_hash  Get the buffer addres and size which holds the hash
 *                         of the realm attestation public key.
 */
void
attest_get_realm_public_key_hash(struct q_useful_buf_c *public_key_hash);

/**
 * \brief Get the realm attestation public key. The public key is included in
 *        the realm attestation token.
 *
 * \param public_key  Get the buffer addres and size which holds the realm
 *                    attestation public key.
 */
void
attest_get_realm_public_key(struct q_useful_buf_c *public_key);


#ifdef __cplusplus
}
#endif

#endif /* __ATTEST_KEY_H__ */
