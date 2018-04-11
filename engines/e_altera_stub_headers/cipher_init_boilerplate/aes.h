#include "omni.h"

OMNI_SETUP_KEYING_PROTO(aes_128);
OMNI_SETUP_KEYING_PROTO(aes_192);
OMNI_SETUP_KEYING_PROTO(aes_256);
OMNI_SETUP_CIPHER_PROTO(aes);

OMNI_SETUP_STRUCT_DATA(aes, AES);
OMNI_SETUP_MIS_STATICS(aes);

OMNI_SETUP_STATIC_CIPHER_MODE(aes, aes_128, ecb, ECB, AES, 16, 16, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(aes, aes_192, ecb, ECB, AES, 16, 24, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(aes, aes_256, ecb, ECB, AES, 16, 32, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(aes, aes_128, ctr, CTR, AES, 16, 16, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(aes, aes_192, ctr, CTR, AES, 16, 24, EVP_CIPH_FLAG_DEFAULT_ASN1);
OMNI_SETUP_STATIC_CIPHER_MODE(aes, aes_256, ctr, CTR, AES, 16, 32, EVP_CIPH_FLAG_DEFAULT_ASN1);

#define CASES_AES_NIDS() \
case NID_aes_128_ecb: \
    *cipher = altera_stub_aes_128_ecb(); \
    break; \
case NID_aes_192_ecb: \
    *cipher = altera_stub_aes_192_ecb(); \
    break; \
case NID_aes_256_ecb: \
    *cipher = altera_stub_aes_256_ecb(); \
    break; \
case NID_aes_128_ctr: \
    *cipher = altera_stub_aes_128_ctr(); \
    break; \
case NID_aes_192_ctr: \
    *cipher = altera_stub_aes_192_ctr(); \
    break; \
case NID_aes_256_ctr: \
    *cipher = altera_stub_aes_256_ctr(); \
    break;
