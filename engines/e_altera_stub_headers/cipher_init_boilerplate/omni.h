#ifndef _ALTERA_STUB_OMNI_H
#define _ALTERA_STUB_OMNI_H

#include "../../opencl_altera/include/opencl_ciphers.h"

#define OMNI_SETUP_CIPHER_PROTO(algo_lowercase) int altera_stub_##algo_lowercase##_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
#define OMNI_SETUP_KEYING_PROTO(algo_keylen_lowercase) int altera_stub_##algo_keylen_lowercase##_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);

#define OMNI_SETUP_STRUCT_DATA(algo_lowercase, algo_uppercase) \
typedef struct { \
    algo_lowercase##_context k; \
    int must_update_iv; \
    int burst_enabled; \
    int enc; \
    union { \
        void (*cipher) (OpenCLEnv* env, uint8_t *in, size_t input_size, algo_lowercase##_context* K, uint8_t *out, cipher_callback_t callback, void *user_data); \
    } stream; \
} EVP_OPENCL_##algo_uppercase##_KEY; \
struct altera_stub_##algo_lowercase##_update_iv_callback_data { \
    EVP_OPENCL_##algo_uppercase##_KEY *data; \
    size_t inl; \
} altera_stub_##algo_lowercase##_update_iv_callback_data;

#define OMNI_SETUP_MIS_STATICS(algo_lowercase)

#define SETUP_CIPHER_IV_CALLBACK(algo_lowercase, inl_size) \
{ \
    if (data->must_update_iv) { \
        callback = &algo_lowercase##_update_iv_callback; \
        user_data = (struct altera_stub_##algo_lowercase##_update_iv_callback_data*) malloc(sizeof(struct altera_stub_##algo_lowercase##_update_iv_callback_data)); \
        user_data->data = data; \
        user_data->inl = inl_size; \
    } else { \
        callback = NULL; \
        user_data = NULL; \
    } \
}

#define OMNI_SETUP_STATIC_CIPHER_MODE(algo_lowercase, algo_keylen_lowercase, mode_lowercase, mode_uppercase, algo_uppercase, blocksize, keysize, global_flags) \
static EVP_CIPHER *_hidden_##algo_keylen_lowercase##_##mode_lowercase = NULL; \
static const EVP_CIPHER *altera_stub_##algo_keylen_lowercase##_##mode_lowercase(void) \
{ \
    if (_hidden_##algo_keylen_lowercase##_##mode_lowercase == NULL \
        && ((_hidden_##algo_keylen_lowercase##_##mode_lowercase = EVP_CIPHER_meth_new(NID_##algo_keylen_lowercase##_##mode_lowercase, \
                                                       blocksize /* block size */, \
                                                       keysize /* key len */)) == NULL \
            || !EVP_CIPHER_meth_set_iv_length(_hidden_##algo_keylen_lowercase##_##mode_lowercase, blocksize) \
            || !EVP_CIPHER_meth_set_flags(_hidden_##algo_keylen_lowercase##_##mode_lowercase, \
                                          global_flags \
                                          | EVP_CIPH_##mode_uppercase##_MODE) \
            || !EVP_CIPHER_meth_set_init(_hidden_##algo_keylen_lowercase##_##mode_lowercase, \
                                         altera_stub_##algo_keylen_lowercase##_init_key) \
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_##algo_keylen_lowercase##_##mode_lowercase, \
                                              altera_stub_##algo_lowercase##_cipher) \
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_##algo_keylen_lowercase##_##mode_lowercase, \
                                                  sizeof(EVP_OPENCL_##algo_uppercase##_KEY)) \
                                              )) { \
        EVP_CIPHER_meth_free(_hidden_##algo_keylen_lowercase##_##mode_lowercase); \
        _hidden_##algo_keylen_lowercase##_##mode_lowercase = NULL; \
    } \
    return _hidden_##algo_keylen_lowercase##_##mode_lowercase; \
}

#define OMNI_SETUP_CIPHER_IMPL(algo_lowercase, algo_uppercase, blocksize) \
static void algo_lowercase##_update_iv_callback(void *user_data) { \
    struct altera_stub_##algo_lowercase##_update_iv_callback_data *p = (struct altera_stub_##algo_lowercase##_update_iv_callback_data*) user_data; \
    opencl_##algo_lowercase##_update_iv_after_chunk_processed(&p->data->k, p->inl); \
} \
int altera_stub_##algo_lowercase##_cipher(EVP_CIPHER_CTX *ctx, \
                           unsigned char *out, \
                           const unsigned char *in, \
                           size_t inl) { \
    EVP_OPENCL_##algo_uppercase##_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx); \
 \
    size_t engine_block_size = OpenCLEnv_get_enc_block_size(global_env); \
    int blocks_inbound = inl / engine_block_size;  /* the reminder is handled by the last (non-burst) block */ \
    int blocks_in_burst = blocks_inbound; \
    if (inl % engine_block_size == 0) {blocks_in_burst--;}  /* no reminder: make a last non-burst block */ \
 \
    size_t reminder = inl - (blocks_in_burst*engine_block_size); \
 \
    struct altera_stub_##algo_lowercase##_update_iv_callback_data *user_data; \
    cipher_callback_t callback; \
 \
    OpenCLEnv_perf_begin_event(global_env); /* The engine also has a standalone performance counter */ \
    OpenCLEnv_toggle_burst_mode(global_env, 1); \
    for (int i=0; i<blocks_in_burst; i++) { \
        SETUP_CIPHER_IV_CALLBACK(algo_lowercase, engine_block_size); \
        (data->stream.cipher) (global_env, \
                               (uint8_t*) (in + engine_block_size*i), \
                               engine_block_size, &data->k, \
                               (uint8_t*) (out + engine_block_size*i), \
                               callback, user_data); \
    } \
    OpenCLEnv_toggle_burst_mode(global_env, 0); \
    SETUP_CIPHER_IV_CALLBACK(algo_lowercase, reminder); \
    (data->stream.cipher) (global_env, \
                           (uint8_t*) (in + engine_block_size*blocks_in_burst), \
                           reminder, &data->k, \
                           (uint8_t*) (out + engine_block_size*blocks_in_burst), \
                           callback, user_data); \
    OpenCLEnv_perf_begin_event(global_env);  /* reset timer again in order to visualize idle times */ \
    return inl; \
}

#define OMNI_SETUP_KEYING_IMPL(algo_lowercase, algo_keylen_lowercase, algo_uppercase, blocksize) \
int altera_stub_##algo_keylen_lowercase##_init_key(EVP_CIPHER_CTX *ctx, \
                                 const unsigned char *key, \
                                 const unsigned char *iv, \
                                 int enc) { \
        int mode = EVP_CIPHER_CTX_mode(ctx) & EVP_CIPH_MODE; \
 \
        EVP_OPENCL_##algo_uppercase##_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx); \
        data->burst_enabled = 0; \
        data->enc = enc; \
 \
        /* key schedule */ \
        if (enc || (mode == EVP_CIPH_CTR_MODE)) { \
            opencl_##algo_keylen_lowercase##_set_encrypt_key( \
                global_env, \
                key, \
                EVP_CIPHER_CTX_key_length(ctx), \
                &data->k); \
        } else { \
            opencl_##algo_keylen_lowercase##_set_decrypt_key( \
                global_env, \
                key, \
                EVP_CIPHER_CTX_key_length(ctx), \
                &data->k); \
        } \
 \
        if (mode == EVP_CIPH_ECB_MODE) { \
            data->stream.cipher = enc ? opencl_##algo_keylen_lowercase##_ecb_encrypt : opencl_##algo_keylen_lowercase##_ecb_decrypt; \
            data->must_update_iv = 0; \
        } else if (mode == EVP_CIPH_CTR_MODE) { \
            opencl_##algo_lowercase##_set_iv(global_env, iv, &data->k); \
            data->stream.cipher = enc ? opencl_##algo_keylen_lowercase##_ctr_encrypt : opencl_##algo_keylen_lowercase##_ctr_decrypt; \
            data->must_update_iv = 1; \
        } \
 \
        else { \
            return 0; \
        } \
 \
        return 1; \
}

#endif
