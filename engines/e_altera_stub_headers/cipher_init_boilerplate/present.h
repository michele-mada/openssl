#include "omni.h"

OMNI_SETUP_KEYING_PROTO(present);
OMNI_SETUP_CIPHER_PROTO(present);

OMNI_SETUP_STRUCT_DATA(present, PRESENT);
OMNI_SETUP_MIS_STATICS(present);

OMNI_SETUP_STATIC_CIPHER_MODE(present, present, ecb, ECB, PRESENT, 8, 10, EVP_CIPH_FLAG_DEFAULT_ASN1);

#define CASES_PRESENT_NIDS() \
case NID_present_ecb: \
    *cipher = altera_stub_present_ecb(); \
    break; \
case NID_present_ctr: \
    *cipher = altera_stub_present_ctr(); \
    break;
