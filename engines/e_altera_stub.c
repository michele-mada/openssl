#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/crypto.h>

#include "e_altera_stub_err.c"

#include "opencl_altera/include/opencl_ciphers.h"
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

#include "e_altera_stub_headers/cipher_init_boilerplate/des.h"
#include "e_altera_stub_headers/cipher_init_boilerplate/aes.h"


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
        case NID_des_ecb:
            *cipher = altera_stub_des_ecb();
            break;
        case NID_aes_128_ecb:
            *cipher = altera_stub_aes_128_ecb();
            break;
        case NID_aes_192_ecb:
            *cipher = altera_stub_aes_192_ecb();
            break;
        case NID_aes_256_ecb:
            *cipher = altera_stub_aes_256_ecb();
            break;
        case NID_aes_128_ctr:
            *cipher = altera_stub_aes_128_ctr();
            break;
        case NID_aes_192_ctr:
            *cipher = altera_stub_aes_192_ctr();
            break;
        case NID_aes_256_ctr:
            *cipher = altera_stub_aes_256_ctr();
            break;
        default:
            ok = 0;
            *cipher = NULL;
            break;
    }
    return ok;
}


/* helper functions */

/*
    If this is the first run, then the fpga won't have any program (or a wrong
    program) loaded.
    This function (called directly after the key setup) processes a dummy buffer;
    This way, the program will be loaded immediately.

    This function exist to facilitate performance measurements.
*/
#define DUMMY_BUF_SIZE 4096*3*5
void pre_program_helper_des(EVP_OPENCL_DES_KEY *data) {
    uint8_t *dummy_in = (uint8_t*) aligned_alloc(AOCL_ALIGNMENT, sizeof(uint8_t) * DUMMY_BUF_SIZE);
    uint8_t *dummy_out = (uint8_t*) aligned_alloc(AOCL_ALIGNMENT, sizeof(uint8_t) * DUMMY_BUF_SIZE);
    (data->stream.cipher) (global_env, dummy_in, DUMMY_BUF_SIZE, &data->k, dummy_out);
    free(dummy_out);
    free(dummy_in);
}
void pre_program_helper_aes(EVP_OPENCL_AES_KEY *data) {
    uint8_t *dummy_in = (uint8_t*) aligned_alloc(AOCL_ALIGNMENT, sizeof(uint8_t) * DUMMY_BUF_SIZE);
    uint8_t *dummy_out = (uint8_t*) aligned_alloc(AOCL_ALIGNMENT, sizeof(uint8_t) * DUMMY_BUF_SIZE);
    (data->stream.cipher) (global_env, dummy_in, DUMMY_BUF_SIZE, &data->k, dummy_out);
    free(dummy_out);
    free(dummy_in);
}

/* des implementation */

int altera_stub_des_init_key(EVP_CIPHER_CTX *ctx,
                             const unsigned char *key,
                             const unsigned char *iv,
                             int enc){
    int mode = EVP_CIPHER_CTX_mode(ctx) & EVP_CIPH_MODE;

    EVP_OPENCL_DES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);

    // key schedule
    opencl_des_set_encrypt_key(
        key,
        EVP_CIPHER_CTX_key_length(ctx),
        &data->k);

    if (mode == EVP_CIPH_ECB_MODE) {
        data->stream.cipher = enc ? opencl_des_ecb_encrypt : opencl_des_ecb_decrypt;
        data->must_update_iv = 0;
    } else if (mode == EVP_CIPH_CTR_MODE) {
        memcpy(data->k.iv, iv, 8);
        data->stream.cipher = enc ? opencl_des_ctr_encrypt : opencl_des_ctr_decrypt;
        data->must_update_iv = 1;
    }

    else {
        return 0;
    }

    pre_program_helper_des(data);

    return 1;
}

int altera_stub_des_cipher(EVP_CIPHER_CTX *ctx,
                           unsigned char *out,
                           const unsigned char *in,
                           size_t inl) {
    EVP_OPENCL_DES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);
    //printf("Block size %ld\n", inl);
    (data->stream.cipher) (global_env, (uint8_t*) in, inl, &data->k, (uint8_t*) out);
    if (data->must_update_iv) {
        opencl_des_update_iv_after_chunk_processed(&data->k, inl);
    }
    return inl;
}

/* aes implementation */

int altera_stub_aes_128_init_key(EVP_CIPHER_CTX *ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv,
                                 int enc){
    int mode = EVP_CIPHER_CTX_mode(ctx) & EVP_CIPH_MODE;

    EVP_OPENCL_AES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);

    // key schedule
    if (enc || (mode == EVP_CIPH_CTR_MODE)) {
        opencl_aes_128_set_encrypt_key(
            key,
            EVP_CIPHER_CTX_key_length(ctx),
            &data->k);
    } else {
        opencl_aes_128_set_decrypt_key(
            key,
            EVP_CIPHER_CTX_key_length(ctx),
            &data->k);
    }

    if (mode == EVP_CIPH_ECB_MODE) {
        data->stream.cipher = enc ? opencl_aes_128_ecb_encrypt : opencl_aes_128_ecb_decrypt;
        data->must_update_iv = 0;
    } else if (mode == EVP_CIPH_CTR_MODE) {
        memcpy(data->k.iv, iv, 16);
        data->stream.cipher = enc ? opencl_aes_128_ctr_encrypt : opencl_aes_128_ctr_decrypt;
        data->must_update_iv = 1;
    }

    else {
        return 0;
    }

    pre_program_helper_aes(data);

    return 1;
}

int altera_stub_aes_192_init_key(EVP_CIPHER_CTX *ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv,
                                 int enc){
    int mode = EVP_CIPHER_CTX_mode(ctx) & EVP_CIPH_MODE;

    EVP_OPENCL_AES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);

    // key schedule
    if (enc || (mode == EVP_CIPH_CTR_MODE)) {
        opencl_aes_192_set_encrypt_key(
            key,
            EVP_CIPHER_CTX_key_length(ctx),
            &data->k);
    } else {
        opencl_aes_192_set_decrypt_key(
            key,
            EVP_CIPHER_CTX_key_length(ctx),
            &data->k);
    }

    if (mode == EVP_CIPH_ECB_MODE) {
        data->stream.cipher = enc ? opencl_aes_192_ecb_encrypt : opencl_aes_192_ecb_decrypt;
        data->must_update_iv = 0;
    } else if (mode == EVP_CIPH_CTR_MODE) {
        memcpy(data->k.iv, iv, 16);
        data->stream.cipher = enc ? opencl_aes_192_ctr_encrypt : opencl_aes_192_ctr_decrypt;
        data->must_update_iv = 1;
    }

    else {
        return 0;
    }

    pre_program_helper_aes(data);

    return 1;
}

int altera_stub_aes_256_init_key(EVP_CIPHER_CTX *ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv,
                                 int enc){
    int mode = EVP_CIPHER_CTX_mode(ctx) & EVP_CIPH_MODE;

    EVP_OPENCL_AES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);

    // key schedule
    if (enc || (mode == EVP_CIPH_CTR_MODE)) {
        opencl_aes_256_set_encrypt_key(
            key,
            EVP_CIPHER_CTX_key_length(ctx),
            &data->k);
    } else {
        opencl_aes_256_set_decrypt_key(
            key,
            EVP_CIPHER_CTX_key_length(ctx),
            &data->k);
    }

    if (mode == EVP_CIPH_ECB_MODE) {
        data->stream.cipher = enc ? opencl_aes_256_ecb_encrypt : opencl_aes_256_ecb_decrypt;
        data->must_update_iv = 0;
    } else if (mode == EVP_CIPH_CTR_MODE) {
        memcpy(data->k.iv, iv, 16);
        data->stream.cipher = enc ? opencl_aes_256_ctr_encrypt : opencl_aes_256_ctr_decrypt;
        data->must_update_iv = 1;
    }

    else {
        return 0;
    }

    pre_program_helper_aes(data);

    return 1;
}

int altera_stub_aes_cipher(EVP_CIPHER_CTX *ctx,
                           unsigned char *out,
                           const unsigned char *in,
                           size_t inl) {
    EVP_OPENCL_AES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);

    size_t engine_block_size = OpenCLEnv_get_enc_block_size(global_env);
    int blocks_inbound = inl / engine_block_size;  // the reminder is handled by the last (non-burst) block
    int blocks_in_burst = blocks_inbound;
    if ((inl % engine_block_size) == 0) blocks_in_burst--;  // no reminder: make a last non-burst block

    size_t reminder = inl - (blocks_in_burst*engine_block_size);
    //printf("bursts: %u = (%u x %u) + %u\n", inl, engine_block_size, blocks_in_burst, reminder);
    OpenCLEnv_perf_begin_event(global_env);  // The engine also has a standalone performance counter
    OpenCLEnv_toggle_burst_mode(global_env, 1);
    for (int i=0; i<blocks_in_burst; i++) {
        (data->stream.cipher) (global_env,
                               (uint8_t*) (in + engine_block_size*i),
                               engine_block_size, &data->k,
                               (uint8_t*) (out + engine_block_size*i));
    }
    OpenCLEnv_toggle_burst_mode(global_env, 0);
    (data->stream.cipher) (global_env,
                           (uint8_t*) (in + engine_block_size*blocks_in_burst),
                           reminder, &data->k,
                           (uint8_t*) (out + engine_block_size*blocks_in_burst));

    if (data->must_update_iv) {
        opencl_aes_update_iv_after_chunk_processed(&data->k, inl);
    }
    return inl;
}
