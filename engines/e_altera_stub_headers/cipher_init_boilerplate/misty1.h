#include "omni.h"

OMNI_SETUP_KEYING_PROTO(misty1);
OMNI_SETUP_CIPHER_PROTO(misty1);

OMNI_SETUP_STRUCT_DATA(misty1, MISTY1);
OMNI_SETUP_MIS_STATICS(misty1);

OMNI_SETUP_STATIC_CIPHER_MODE(misty1, misty1, ecb, ECB, MISTY1, 8, 16, EVP_CIPH_FLAG_DEFAULT_ASN1);

#define CASES_MISTY1_NIDS() \
case NID_misty1_ecb: \
    *cipher = altera_stub_misty1_ecb(); \
    break; \
case NID_misty1_ctr: \
    *cipher = altera_stub_misty1_ctr(); \
    break;
