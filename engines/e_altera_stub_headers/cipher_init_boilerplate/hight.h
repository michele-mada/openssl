#include "omni.h"

OMNI_SETUP_KEYING_PROTO(hight);
OMNI_SETUP_CIPHER_PROTO(hight);

OMNI_SETUP_STRUCT_DATA(hight, HIGHT);
OMNI_SETUP_MIS_STATICS(hight);

OMNI_SETUP_STATIC_CIPHER_MODE(hight, hight, ecb, ECB, HIGHT, 8, 16, EVP_CIPH_FLAG_DEFAULT_ASN1);

#define CASES_HIGHT_NIDS() \
case NID_hight_ecb: \
    *cipher = altera_stub_hight_ecb(); \
    break; \
case NID_hight_ctr: \
    *cipher = altera_stub_hight_ctr(); \
    break;
