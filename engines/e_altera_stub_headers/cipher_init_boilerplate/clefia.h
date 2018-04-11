#include "omni.h"

OMNI_SETUP_KEYING_PROTO(clefia_128);
OMNI_SETUP_KEYING_PROTO(clefia_192);
OMNI_SETUP_KEYING_PROTO(clefia_256);
OMNI_SETUP_CIPHER_PROTO(clefia);

OMNI_SETUP_STRUCT_DATA(clefia, CLEFIA);
OMNI_SETUP_MIS_STATICS(clefia);

OMNI_SETUP_STATIC_CIPHER_MODE(clefia, clefia_128, ecb, ECB, CLEFIA, 16, 16, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(clefia, clefia_192, ecb, ECB, CLEFIA, 16, 24, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(clefia, clefia_256, ecb, ECB, CLEFIA, 16, 32, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(clefia, clefia_128, ctr, CTR, CLEFIA, 16, 16, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(clefia, clefia_192, ctr, CTR, CLEFIA, 16, 24, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(clefia, clefia_256, ctr, CTR, CLEFIA, 16, 32, EVP_CIPH_FLAG_DEFAULT_ASN1);

#define CASES_CLEFIA_NIDS() \
case NID_clefia_128_ecb: \
    *cipher = altera_stub_clefia_128_ecb(); \
    break; \
case NID_clefia_192_ecb: \
    *cipher = altera_stub_clefia_192_ecb(); \
    break; \
case NID_clefia_256_ecb: \
    *cipher = altera_stub_clefia_256_ecb(); \
    break; \
case NID_clefia_128_ctr: \
    *cipher = altera_stub_clefia_128_ctr(); \
    break; \
case NID_clefia_192_ctr: \
    *cipher = altera_stub_clefia_192_ctr(); \
    break; \
case NID_clefia_256_ctr: \
    *cipher = altera_stub_clefia_256_ctr(); \
    break;\
