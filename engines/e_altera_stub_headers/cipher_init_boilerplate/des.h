#include "omni.h"

OMNI_SETUP_KEYING_PROTO(des);
OMNI_SETUP_CIPHER_PROTO(des);

OMNI_SETUP_STRUCT_DATA(des, DES);
OMNI_SETUP_MIS_STATICS(des);

OMNI_SETUP_STATIC_CIPHER_MODE(des, des, ecb, ECB, DES, 8, 8, EVP_CIPH_FLAG_DEFAULT_ASN1);

#define CASES_DES_NIDS() \
case NID_des_ecb: \
    *cipher = altera_stub_des_ecb(); \
    break;
