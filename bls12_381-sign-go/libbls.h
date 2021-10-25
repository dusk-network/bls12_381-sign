/* libbls Header Version 0.1.0 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

const int SK_SIZE = 32;
const int SIG_SIZE = 48;
const int PK_SIZE = 96;

typedef enum {
	BLS_OK = 0,
	BLS_INVALID_BYTES = 1,
	BLS_VERIFICATION_FAILED = 2,
} bls_sign_status;

void generate_keys(const uint8_t *sk_ptr,
		const uint8_t *pk_ptr);

bls_sign_status sign(const uint8_t *sk_ptr, 
		const uint8_t *pk_ptr, 
		const uint8_t *msg_ptr, 
		size_t msg_len,
		const uint8_t *sig_ptr);

bls_sign_status verify(const uint8_t *apk_ptr, 
		const uint8_t *sig_ptr, 
		const uint8_t *msg_ptr, 
		size_t msg_len);

bls_sign_status create_apk(const uint8_t *pk_ptr,
		const uint8_t *apk_ptr);

bls_sign_status aggregate_pk(const uint8_t *apk_ptr, 
		const uint8_t *pk_ptr, 
		size_t pk_len,
		const uint8_t *ret_ptr);

bls_sign_status aggregate_sig(const uint8_t *sig_ptr, 
		const uint8_t *sigs_ptr, 
		size_t sigs_len,
		const uint8_t *ret_ptr);
