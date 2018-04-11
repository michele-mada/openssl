#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/crypto.h>

//TODO: refactor in order to avoid accessing internal openssl data structures like this
#include "../crypto/evp/evp_locl.h"
#include "../crypto/include/internal/evp_int.h"

#include "e_altera_stub_err.c"

#include "opencl_altera/include/opencl_ciphers.h"
#include "e_altera_stub_headers/utils.h"
#include "e_altera_stub_headers/aligned_mem_management.h"

/* Engine Id and Name */
static const char *engine_altera_stub_id = "altera_stub";
static const char *engine_altera_stub_name = "Altera stub engine, work in progress";

static OpenCLEnv *global_env;

/* Engine Lifetime functions */
static int altera_stub_destroy(ENGINE *e);
static int altera_stub_init(ENGINE *e);
static int altera_stub_finish(ENGINE *e);
void ENGINE_load_altera_stub(void);

/* setup functions */
/* Setup ciphers */
static int altera_stub_ciphers(ENGINE *, const EVP_CIPHER **,
                               const int **, int);

static int altera_stub_cipher_nids[] = {
    NID_des_ecb,
    NID_aes_128_ecb,
    NID_aes_192_ecb,
    NID_aes_256_ecb,
    NID_aes_128_ctr,
    NID_aes_192_ctr,
    NID_aes_256_ctr,

    0
};

#include "e_altera_stub_headers/cipher_init_boilerplate/all.h"


static int bind_altera_stub(ENGINE *e)
{
    /* Ensure the ossltest error handling is set up */
    ERR_load_ALTERASTUB_strings();
    if (!ENGINE_set_id(e, engine_altera_stub_id)
        || !ENGINE_set_name(e, engine_altera_stub_name)
        //|| !ENGINE_set_digests(e, ossltest_digests)
        || !ENGINE_set_ciphers(e, altera_stub_ciphers)
        || !ENGINE_set_destroy_function(e, altera_stub_destroy)
        || !ENGINE_set_init_function(e, altera_stub_init)
        || !ENGINE_set_finish_function(e, altera_stub_finish)) {
        ALTERASTUBerr(ALTERASTUB_F_BIND_ALTERA_STUB, ALTERASTUB_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id) {
    if (id && (strcmp(id, engine_altera_stub_id) != 0))
        return 0;
    if (!bind_altera_stub(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)


#endif

static ENGINE *engine_altera_stub(void) {
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_altera_stub(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_altera_stub(void) {
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_altera_stub();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


static int altera_stub_init(ENGINE *e) {
    global_env = OpenCLEnv_init();
    size_t engine_block_size = OpenCLEnv_get_enc_block_size(global_env);
    size_t multiplier = 20;
    char *custom_multiplier = getenv("OCLC_ENGINE_MULTIPLIER");
    if (custom_multiplier != NULL) {
        multiplier = atol(custom_multiplier);
    }
    int status = ENGINE_set_enc_block_size(e, engine_block_size * multiplier);

    return status && (global_env != NULL);
}


static int altera_stub_finish(ENGINE *e) {
    OpenCLEnv_destroy(global_env);
    return 1;
}


static int altera_stub_destroy(ENGINE *e) {
    //destroy_digests();
    //destroy_ciphers();
    ERR_unload_ALTERASTUB_strings();
    return 1;
}

static int altera_stub_ciphers(ENGINE *e,
                               const EVP_CIPHER **cipher,
                               const int **nids,
                               int nid) {
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = altera_stub_cipher_nids;
        return (sizeof(altera_stub_cipher_nids) - 1)
               / sizeof(altera_stub_cipher_nids[0]);
    }
    /* We are being asked for a specific cipher */
    switch (nid) {
        CASES_AES_NIDS();
        CASES_DES_NIDS();
        CASES_CAMELLIA_NIDS();
        CASES_CAST5_NIDS();
        //CASES_CLEFIA_NIDS();
        //CASES_HIGHT_NIDS();
        //CASES_MISTY1_NIDS();
        ///CASES_PRESENT_NIDS();
        CASES_SEED_NIDS();
        default:
            ok = 0;
            *cipher = NULL;
            break;
    }
    return ok;
}

/* des implementation */

OMNI_SETUP_KEYING_IMPL(des, des, DES, 8);

OMNI_SETUP_CIPHER_IMPL(des, DES, 8);

/* aes implementation */

OMNI_SETUP_KEYING_IMPL(aes, aes_128, AES, 16);
OMNI_SETUP_KEYING_IMPL(aes, aes_192, AES, 16);
OMNI_SETUP_KEYING_IMPL(aes, aes_256, AES, 16);

OMNI_SETUP_CIPHER_IMPL(aes, AES, 16);
