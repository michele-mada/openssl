#include "../../opencl_altera/include/opencl_ciphers.h"

/* setup DES */
int altera_stub_des_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int altera_stub_des_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

typedef struct {
    des_context k;
    int must_update_iv;
    union {
        void (*cipher) (OpenCLEnv* env, uint8_t *in, size_t input_size, des_context* K, uint8_t *out);
    } stream;
} EVP_OPENCL_DES_KEY;

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
                                              altera_stub_des_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_des_ecb,
                                                  sizeof(EVP_OPENCL_DES_KEY))
                                              )) {
        EVP_CIPHER_meth_free(_hidden_des_ecb);
        _hidden_des_ecb = NULL;
    }
    return _hidden_des_ecb;
}
