#include "../opencl_altera/include/opencl_ciphers.h"

/* setup AES */
int altera_stub_aes_128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int altera_stub_aes_192_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int altera_stub_aes_256_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int altera_stub_aes_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

typedef struct {
    aes_context k;
    int must_update_iv;
    union {
        void (*cipher) (OpenCLEnv* env, uint8_t *in, size_t input_size, aes_context* K, uint8_t *out);
    } stream;
} EVP_OPENCL_AES_KEY;

static EVP_CIPHER *_hidden_aes_128_ecb = NULL;
static const EVP_CIPHER *altera_stub_aes_128_ecb(void)
{
    if (_hidden_aes_128_ecb == NULL
        && ((_hidden_aes_128_ecb = EVP_CIPHER_meth_new(NID_aes_128_ecb,
                                                       16 /* block size */,
                                                       16 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_ecb, 16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_128_ecb,
                                          EVP_CIPH_FLAG_DEFAULT_ASN1
                                          | EVP_CIPH_ECB_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_128_ecb,
                                         altera_stub_aes_128_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_ecb,
                                              altera_stub_aes_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_ecb,
                                                  sizeof(EVP_OPENCL_AES_KEY))
                                              )) {
        EVP_CIPHER_meth_free(_hidden_aes_128_ecb);
        _hidden_aes_128_ecb = NULL;
    }
    return _hidden_aes_128_ecb;
}

static EVP_CIPHER *_hidden_aes_192_ecb = NULL;
static const EVP_CIPHER *altera_stub_aes_192_ecb(void)
{
    if (_hidden_aes_192_ecb == NULL
        && ((_hidden_aes_192_ecb = EVP_CIPHER_meth_new(NID_aes_192_ecb,
                                                       16 /* block size */,
                                                       24 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_192_ecb, 16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_192_ecb,
                                          EVP_CIPH_FLAG_DEFAULT_ASN1
                                          | EVP_CIPH_ECB_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_192_ecb,
                                         altera_stub_aes_192_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_192_ecb,
                                              altera_stub_aes_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_192_ecb,
                                                  sizeof(EVP_OPENCL_AES_KEY))
                                              )) {
        EVP_CIPHER_meth_free(_hidden_aes_192_ecb);
        _hidden_aes_192_ecb = NULL;
    }
    return _hidden_aes_192_ecb;
}

static EVP_CIPHER *_hidden_aes_256_ecb = NULL;
static const EVP_CIPHER *altera_stub_aes_256_ecb(void)
{
    if (_hidden_aes_256_ecb == NULL
        && ((_hidden_aes_256_ecb = EVP_CIPHER_meth_new(NID_aes_256_ecb,
                                                       16 /* block size */,
                                                       32 /* key len */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_ecb, 16)
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_ecb,
                                          EVP_CIPH_FLAG_DEFAULT_ASN1
                                          | EVP_CIPH_ECB_MODE)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_ecb,
                                         altera_stub_aes_256_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_ecb,
                                              altera_stub_aes_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_ecb,
                                                  sizeof(EVP_OPENCL_AES_KEY))
                                              )) {
        EVP_CIPHER_meth_free(_hidden_aes_256_ecb);
        _hidden_aes_256_ecb = NULL;
    }
    return _hidden_aes_256_ecb;
}
