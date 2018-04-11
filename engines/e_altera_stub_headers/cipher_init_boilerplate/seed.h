#include "omni.h"

OMNI_SETUP_KEYING_PROTO(seed);
OMNI_SETUP_CIPHER_PROTO(seed);

OMNI_SETUP_STRUCT_DATA(seed, SEED);
OMNI_SETUP_MIS_STATICS(seed);

OMNI_SETUP_STATIC_CIPHER_MODE(seed, seed, ecb, ECB, SEED, 8, 16, EVP_CIPH_FLAG_DEFAULT_ASN1);

#define CASES_SEED_NIDS() \
case NID_seed_ecb: \
    *cipher = altera_stub_seed_ecb(); \
    break; \
/**case NID_seed_ctr: \
    *cipher = altera_stub_seed_ctr(); \
    break;*/
