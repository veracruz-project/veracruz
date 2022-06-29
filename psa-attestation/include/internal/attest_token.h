#ifndef __ATTEST_TOKEN_H__
#define __ATTEST_TOKEN_H__

#include <qcbor/qcbor.h>
#include <t_cose/t_cose_sign1_sign.h>

enum attest_token_err_t {
	/** Success */
	ATTEST_TOKEN_ERR_SUCCESS = 0,
	/** The buffer passed in to receive the output is too small. */
	ATTEST_TOKEN_ERR_TOO_SMALL,
	/** Something went wrong formatting the CBOR, most likely the
	 payload has maps or arrays that are not closed. */
	ATTEST_TOKEN_ERR_CBOR_FORMATTING,
	/** Signing key is not found or of wrong type. */
	ATTEST_TOKEN_ERR_SIGNING_KEY,
	/** TODO: Might use the error mapping from TF-M. */
	ATTEST_TOKEN_ERR_COSE_ERROR,
	/** Signing is in progress, function should be called with the same
	 parameters again. */
	ATTEST_TOKEN_ERR_COSE_SIGN_IN_PROGRESS
};

#define ATTEST_CHALLENGE_SIZE 64
#define ATTEST_TOKEN_BUFFER_SIZE (4 * 1024) /* 4KB */

#define TAG_COSE_SIGN1                     (18)
#define TAG_CCA_PLATFORM_TOKEN             (25000)

#define CCA_PLAT_VERIFICATION_SERVICE (-75010)
#define CCA_PLAT_INSTANCE_ID		  (-75009)
#define CCA_PLAT_NONCE				  (-75008)
#define CCA_PLAT_SW_COMPONENTS        (-75006)
#define CCA_PLAT_BOOT_SEED			  (-75004)
#define CCA_PLAT_IMPLEMENTATION_ID    (-75003)
#define CCA_PLAT_SECURITY_LIFECYCLE   (-75002)
#define CCA_PLAT_PARTITION_ID		  (-75001)
#define CCA_PLAT_CHALLENGE                (10)
#define CCA_PLAT_UEID                     (11)
#define CCA_PLAT_PROFILE_DEFINITION       (18)

#define CCA_REALM_VERIFICATION_SERVICE          (-75010)
#define CCA_REALM_CHALLENGE                         (10)
#define CCA_REALM_PROFILE                           (18)
#define CCA_REALM_IDENTITY                       (25101)
#define CCA_REALM_DEBUG                          (25102)
#define CCA_REALM_SEEDS                          (25103)
#define CCA_REALM_HASH_ALGM_ID                   (25104)
#define CCA_REALM_PUB_KEY                        (25105)

#define CCA_SW_COMP_MEASUREMENT_TYPE  (1)
#define CCA_SW_COMP_MEASUREMENT_VALUE (2)
#define CCA_SW_COMP_VERSION           (4)
#define CCA_SW_COMP_SIGNER_ID         (5)
#define CCA_SW_COMP_HASH_ALGORITHM    (6)

#define REALM_MEASUREMENT_ALGO_SHA256	1

/**
 * The context for creating an attestation token.  The caller of
 * attest_token_encode must create one of these and pass it to the functions
 * here. It is small enough that it can go on the stack. It is most of
 * the memory needed to create a token except the output buffer and
 * any memory requirements for the cryptographic operations.
 *
 * The structure is opaque for the caller.
 *
 * This is roughly 148 + 8 + 32 = 188 bytes
 */
struct attest_token_encode_ctx {
	/* Private data structure */
	QCBOREncodeContext                   cbor_enc_ctx;
	uint32_t                             opt_flags;
	int32_t                              key_select;
	struct t_cose_sign1_sign_ctx         signer_ctx;
	//struct t_cose_sign1_sign_restart_ctx signer_restart_ctx;
};

enum attest_token_err_t
attest_token_encode_start(struct attest_token_encode_ctx *me,
			  uint32_t opt_flags,
			  int32_t key_select,
			  int32_t cose_alg_id,
			  const struct q_useful_buf *out_buf);

enum attest_token_err_t
attest_token_encode_finish(struct attest_token_encode_ctx *cbor_enc_ctx,
			  struct q_useful_buf_c *completed_token);

void attest_token_encode_add_integer(struct attest_token_encode_ctx *me,
				     int32_t label,
				     int64_t Value);

void attest_token_encode_add_bool(struct attest_token_encode_ctx *me,
				  int32_t label,
				  int64_t claim);

void attest_token_encode_add_bstr(struct attest_token_encode_ctx *me,
				  int32_t label,
				  const struct q_useful_buf_c *bstr);

void attest_token_encode_add_raw_bstr(struct attest_token_encode_ctx *me,
				      const struct q_useful_buf_c *bstr);

void attest_token_encode_add_tstr(struct attest_token_encode_ctx *me,
				  int32_t label,
				  const struct q_useful_buf_c *tstr);

void attest_token_encode_open_array_in_map(struct attest_token_encode_ctx *me,
					   int32_t label);

void attest_token_encode_close_array(struct attest_token_encode_ctx *me);

void attest_token_encode_close_map(struct attest_token_encode_ctx *me);

#endif // __ATTEST_TOKEN_H__