/*
 * Copyright (c) 2018-2019, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2020-2021, Arm Limited or its affiliates.
 * ALL RIGHTS RESERVED
 */

/* This file is derived from:
 *    trusted-firmware-m/secure_fw/partitions/initial_attestation/attest_token_encode.c
 */

#include <assert.h>
#include "attest_token.h"
#include "attest_key.h"
#include "qcbor/qcbor.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"

/*
 * Outline of token creation. Much of this occurs inside
 * t_cose_sign1_encode_parameters() and t_cose_sign1_encode_signature().
 *
 * - Create encoder context
 * - Open the CBOR array that hold the \c COSE_Sign1
 * - Write COSE Headers
 *   - Protected Header
 *      - Algorithm ID
 *   - Unprotected Headers
 *     - Key ID
 * - Open payload bstr
 *   - Write payload data, maybe lots of it
 *   - Get bstr that is the encoded payload
 * - Compute signature
 *   - Create a separate encoder context for \c Sig_structure
 *     - Encode CBOR context identifier
 *     - Encode protected headers
 *     - Encode two empty bstr
 *     - Add one more empty bstr that is a "fake payload"
 *     - Close off \c Sig_structure
 *   - Hash all but "fake payload" of \c Sig_structure
 *   - Get payload bstr ptr and length
 *   - Continue hash of the real encoded payload
 *   - Run ECDSA
 * - Write signature into the CBOR output
 * - Close CBOR array holding the \c COSE_Sign1
 */

enum attest_token_err_t
attest_token_encode_start(struct attest_token_encode_ctx *me,
			  uint32_t opt_flags,
			  int32_t key_select,
			  int32_t cose_alg_id,
			  const struct q_useful_buf *out_buf)
{
	enum t_cose_err_t cose_res;
	int32_t t_cose_options = 0;
	struct t_cose_key attest_key;
	const mbedtls_ecp_keypair *signing_key;
	struct q_useful_buf_c attest_key_id = NULL_Q_USEFUL_BUF_C;

	/* Remember some of the configuration values */
	me->opt_flags  = opt_flags;
	me->key_select = key_select;

	t_cose_sign1_sign_init(&(me->signer_ctx),
					       t_cose_options,
					       cose_alg_id);

	//attest_get_realm_signing_key(&signing_key);
	attest_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;
	attest_key.k.key_handle = key_select; //(void *)signing_key;

	t_cose_sign1_set_signing_key(&(me->signer_ctx),
				     attest_key,
				     attest_key_id);

	/* Spin up the CBOR encoder */
	QCBOREncode_Init(&(me->cbor_enc_ctx), *out_buf);

	/* This will cause the cose headers to be encoded and written into
	 *  out_buf using me->cbor_enc_ctx
	 */
	cose_res = t_cose_sign1_encode_parameters(&(me->signer_ctx),
						  &(me->cbor_enc_ctx));
	if (cose_res) {
		return ATTEST_TOKEN_ERR_COSE_ERROR;
	}

	QCBOREncode_OpenMap(&(me->cbor_enc_ctx));
	return ATTEST_TOKEN_ERR_SUCCESS;
}

enum attest_token_err_t
attest_token_encode_finish(struct attest_token_encode_ctx *encode_ctx,
			  struct q_useful_buf_c *completed_token)
{
	/* The completed and signed encoded cose_sign1 */
	struct q_useful_buf_c   completed_token_ub;
	enum attest_token_err_t attest_res = ATTEST_TOKEN_ERR_SUCCESS;
	QCBORError              qcbor_res;
	enum t_cose_err_t       cose_res;

	/* -- Finish up the COSE_Sign1. This is where the signing happens -- */
	printf("calling t_cose_sign1_encode_signature\n");
	cose_res = t_cose_sign1_encode_signature(
					&(encode_ctx->signer_ctx),
					&(encode_ctx->cbor_enc_ctx));
	// if (cose_res == T_COSE_ERR_SIG_IN_PROGRESS) {
	// 	/* Token signing has not yet finished */
	// 	return ATTEST_TOKEN_ERR_COSE_SIGN_IN_PROGRESS;
	// }

	if (cose_res) {
		printf("t_cose_sign1_encode_signature failed with code:%d\n", cose_res);
		/* Main errors are invoking the hash or signature */
		return ATTEST_TOKEN_ERR_COSE_ERROR;
	}

	/* Finally close off the CBOR formatting and get the pointer and length
	 * of the resulting COSE_Sign1
	 */
	qcbor_res = QCBOREncode_Finish(&(encode_ctx->cbor_enc_ctx),
				       &completed_token_ub);
	if (qcbor_res == QCBOR_ERR_BUFFER_TOO_SMALL) {
		attest_res = ATTEST_TOKEN_ERR_TOO_SMALL;
	} else if (qcbor_res != QCBOR_SUCCESS) {
		/* likely from array not closed, too many closes, ... */
		attest_res = ATTEST_TOKEN_ERR_CBOR_FORMATTING;
	} else {
		*completed_token = completed_token_ub;
	}

	return attest_res;
}

void attest_token_encode_add_integer(struct attest_token_encode_ctx *me,
				     int32_t label,
				     int64_t Value)
{
	QCBOREncode_AddInt64ToMapN(&(me->cbor_enc_ctx), label, Value);
}

void attest_token_encode_add_bool(struct attest_token_encode_ctx *me,
				  int32_t label,
				  int64_t claim)
{
	QCBOREncode_AddBoolToMapN(&(me->cbor_enc_ctx), label, claim);
}

void attest_token_encode_add_bstr(struct attest_token_encode_ctx *me,
				  int32_t label,
				  const struct q_useful_buf_c *bstr)
{
	QCBOREncode_AddBytesToMapN(&(me->cbor_enc_ctx),
				   label,
				   *bstr);
}

void attest_token_encode_add_raw_bstr(struct attest_token_encode_ctx *me,
				      const struct q_useful_buf_c *bstr)
{
	QCBOREncode_AddBytes(&(me->cbor_enc_ctx), *bstr);
}

void attest_token_encode_add_tstr(struct attest_token_encode_ctx *me,
				  int32_t label,
				  const struct q_useful_buf_c *tstr)
{
	QCBOREncode_AddTextToMapN(&(me->cbor_enc_ctx), label, *tstr);
}

void attest_token_encode_open_array_in_map(struct attest_token_encode_ctx *me,
					   int32_t label)
{
	QCBOREncode_OpenArrayInMapN(&(me->cbor_enc_ctx), label);
}

void attest_token_encode_close_array(struct attest_token_encode_ctx *me)
{
	QCBOREncode_CloseArray(&(me->cbor_enc_ctx));
}

void attest_token_encode_close_map(struct attest_token_encode_ctx *me)
{
	QCBOREncode_CloseMap(&(me->cbor_enc_ctx));
}
