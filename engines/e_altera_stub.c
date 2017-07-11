#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/crypto.h>

#include "e_altera_stub_err.c"

#include "opencl_altera/include/opencl_ciphers.h"

/* Engine Id and Name */
static const char *engine_altera_stub_id = "altera_stub";
static const char *engine_altera_stub_name = "Altera stub engine, work in progress";

static OpenCL_ENV *global_env;

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
    NID_des_ecb, 0
};

/* setup DES */
int altera_stub_des_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int altera_stub_des_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

static EVP_CIPHER *_hidden_des_ecb = NULL;
static const EVP_CIPHER *altera_stub_des_ecb(void)
{
    if (_hidden_des_ecb == NULL
        && ((_hidden_des_ecb = EVP_CIPHER_meth_new(NID_des_ecb,
                                                       8 /* block size */,
                                                       8 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_des_ecb, 8)
            || !EVP_CIPHER_meth_set_flags(_hidden_des_ecb,
                                          EVP_CIPH_FLAG_DEFAULT_ASN1
                                          | EVP_CIPH_ECB_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_des_ecb,
                                         altera_stub_des_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_des_ecb,
                                              altera_stub_des_ecb_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_des_ecb,
                                                  EVP_CIPHER_impl_ctx_size(EVP_des_ecb())))) {
        EVP_CIPHER_meth_free(_hidden_des_ecb);
        _hidden_des_ecb = NULL;
    }
    return _hidden_des_ecb;
}




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
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_altera_stub_id) != 0))
        return 0;
    if (!bind_altera_stub(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

static ENGINE *engine_altera_stub(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_altera_stub(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_altera_stub(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_altera_stub();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}


static int altera_stub_init(ENGINE *e)
{
    global_env = init_OpenCL_ENV();
    return 1;
}


static int altera_stub_finish(ENGINE *e)
{
    destroy_OpenCL_ENV(global_env);
    return 1;
}


static int altera_stub_destroy(ENGINE *e)
{
    //destroy_digests();
    //destroy_ciphers();
    ERR_unload_ALTERASTUB_strings();
    return 1;
}

static int altera_stub_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                               const int **nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = altera_stub_cipher_nids;
        return (sizeof(altera_stub_cipher_nids) - 1)
               / sizeof(altera_stub_cipher_nids[0]);
    }
    /* We are being asked for a specific cipher */
    switch (nid) {
    case NID_des_ecb:
        *cipher = altera_stub_des_ecb();
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}


/* des implementation */

int altera_stub_des_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    int mode = EVP_CIPHER_CTX_mode(ctx);
    opencl_des_set_encrypt_key(
        key,
        EVP_CIPHER_CTX_key_length(ctx),
        EVP_CIPHER_CTX_get_cipher_data(ctx));
    return 1;
}

int altera_stub_des_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    des_context *K = EVP_CIPHER_CTX_get_cipher_data(ctx);
    opencl_des_ecb_encrypt(global_env, in, inl, K, out);

    return 1;
}
