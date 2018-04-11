#include "omni.h"

OMNI_SETUP_KEYING_PROTO(cast5);
OMNI_SETUP_CIPHER_PROTO(cast5);

OMNI_SETUP_STRUCT_DATA(cast5, CAST5);
OMNI_SETUP_MIS_STATICS(cast5);

OMNI_SETUP_STATIC_CIPHER_MODE(cast5, cast5, ecb, ECB, CAST5, 8, 10, EVP_CIPH_FLAG_DEFAULT_ASN1);

#define CASES_CAST5_NIDS() \
case NID_cast5_ecb: \
    *cipher = altera_stub_cast5_ecb(); \
    break; \
/*case NID_cast5_ctr: \
    *cipher = altera_stub_cast5_ctr(); \
    break;*/
