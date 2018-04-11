#include "omni.h"

OMNI_SETUP_KEYING_PROTO(camellia_128);
OMNI_SETUP_KEYING_PROTO(camellia_192);
OMNI_SETUP_KEYING_PROTO(camellia_256);
OMNI_SETUP_CIPHER_PROTO(camellia);

OMNI_SETUP_STRUCT_DATA(camellia, CAMELLIA);
OMNI_SETUP_MIS_STATICS(camellia);

OMNI_SETUP_STATIC_CIPHER_MODE(camellia, camellia_128, ecb, ECB, CAMELLIA, 16, 16, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(camellia, camellia_192, ecb, ECB, CAMELLIA, 16, 24, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(camellia, camellia_256, ecb, ECB, CAMELLIA, 16, 32, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(camellia, camellia_128, ctr, CTR, CAMELLIA, 16, 16, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(camellia, camellia_192, ctr, CTR, CAMELLIA, 16, 24, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(camellia, camellia_256, ctr, CTR, CAMELLIA, 16, 32, EVP_CIPH_FLAG_DEFAULT_ASN1);

#define CASES_CAMELLIA_NIDS() \
case NID_camellia_128_ecb: \
    *cipher = altera_stub_camellia_128_ecb(); \
    break; \
case NID_camellia_192_ecb: \
    *cipher = altera_stub_camellia_192_ecb(); \
    break; \
case NID_camellia_256_ecb: \
    *cipher = altera_stub_camellia_256_ecb(); \
    break; \
case NID_camellia_128_ctr: \
    *cipher = altera_stub_camellia_128_ctr(); \
    break; \
case NID_camellia_192_ctr: \
    *cipher = altera_stub_camellia_192_ctr(); \
    break; \
case NID_camellia_256_ctr: \
    *cipher = altera_stub_camellia_256_ctr(); \
    break;\
