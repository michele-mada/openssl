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
    int status = ENGINE_set_enc_block_size(e, engine_block_size);
    pthread_mutex_init(&altera_stub_aes_mutex, NULL);
    pthread_mutex_init(&altera_stub_des_mutex, NULL);
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
    (data->stream.cipher) (global_env, dummy_in, DUMMY_BUF_SIZE, &data->k, dummy_out, NULL, NULL);
    free(dummy_out);
    free(dummy_in);
}

/* des implementation */

int altera_stub_des_init_key(EVP_CIPHER_CTX *ctx,
                             const unsigned char *key,
                             const unsigned char *iv,
                             int enc) \
    GUARD_DECORATOR(altera_stub_des_mutex,
    {
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
    })

int altera_stub_des_cipher(EVP_CIPHER_CTX *ctx,
                           unsigned char *out,
                           const unsigned char *in,
                           size_t inl) \
    GUARD_DECORATOR(altera_stub_des_mutex,
    {
        EVP_OPENCL_DES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);
        //printf("Block size %ld\n", inl);
        (data->stream.cipher) (global_env, (uint8_t*) in, inl, &data->k, (uint8_t*) out);
        if (data->must_update_iv) {
            opencl_des_update_iv_after_chunk_processed(&data->k, inl);
        }
        return inl;
    })

/* aes implementation */

int altera_stub_aes_128_init_key(EVP_CIPHER_CTX *ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv,
                                 int enc) \
    GUARD_DECORATOR(altera_stub_aes_mutex,
    {
        int mode = EVP_CIPHER_CTX_mode(ctx) & EVP_CIPH_MODE;

        EVP_OPENCL_AES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);
        data->burst_enabled = 0;
        data->enc = enc;

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
    })

int altera_stub_aes_192_init_key(EVP_CIPHER_CTX *ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv,
                                 int enc) \
    GUARD_DECORATOR(altera_stub_aes_mutex,
    {
        int mode = EVP_CIPHER_CTX_mode(ctx) & EVP_CIPH_MODE;

        EVP_OPENCL_AES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);
        data->burst_enabled = 0;
        data->enc = enc;

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
    })

int altera_stub_aes_256_init_key(EVP_CIPHER_CTX *ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv,
                                 int enc) \
    GUARD_DECORATOR(altera_stub_aes_mutex,
    {
        int mode = EVP_CIPHER_CTX_mode(ctx) & EVP_CIPH_MODE;

        EVP_OPENCL_AES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);
        data->burst_enabled = 0;
        data->enc = enc;

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
    })

int altera_stub_aes_cipher_inner(EVP_CIPHER_CTX *ctx,
                                 unsigned char *out,
                                 const unsigned char *in,
                                 size_t inl,
                                 int is_final) {
    EVP_OPENCL_AES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);

    // Note: it is the specific CipherMethod implementing this function
    //       that will handle the burst mode;
    //       in other words, if the CipherMethod does not have a burst mode,
    //       calling OpenCLEnv_toggle_burst_mode will do nothing
    /*if (!is_final) {
        if (!data->burst_enabled) {
            OpenCLEnv_perf_begin_event(global_env);  // The engine also has a standalone performance counter
            OpenCLEnv_toggle_burst_mode(global_env, 1);
            data->burst_enabled = 1;
        }
    } else {
        if (data->burst_enabled) {
            OpenCLEnv_toggle_burst_mode(global_env, 0);
            data->burst_enabled = 0;
        }
    }*/

    (data->stream.cipher) (global_env,
                           (uint8_t*) in,
                           inl, &data->k,
                           (uint8_t*) out,
                           NULL, NULL);

    if (is_final) {
        OpenCLEnv_perf_begin_event(global_env);  // reset timer again in order to visualize idle times
    }

    if (data->must_update_iv) {
        opencl_aes_update_iv_after_chunk_processed(&data->k, inl);
    }
    return inl;
}

int altera_stub_aes_cipher(EVP_CIPHER_CTX *ctx,
                                 unsigned char *out,
                                 const unsigned char *in,
                                 size_t inl) {
    altera_stub_aes_cipher_inner(ctx, out, in, inl, 0);
}

// If aes is a custom cipher, we have to implement a couple of EVP_* functions
// by ourselves
// the best way to do it is copying them
// (see openssl/crypto/evp/evp_enc.c)


#define PTRDIFF_T uint64_t

int is_partially_overlapping(const void *ptr1, const void *ptr2, int len)
{
    PTRDIFF_T diff = (PTRDIFF_T)ptr1-(PTRDIFF_T)ptr2;
    /*
     * Check for partially overlapping buffers. [Binary logical
     * operations are used instead of boolean to minimize number
     * of conditional branches.]
     */
    int overlapped = (len > 0) & (diff != 0) & ((diff < (PTRDIFF_T)len) |
                                                (diff > (0 - (PTRDIFF_T)len)));

    return overlapped;
}

int altera_stub_aes_encrypt_update(EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl,
                                   const unsigned char *in, int inl) {
    int i, j, bl, cmpl = inl;

    if (EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS))
       cmpl = (cmpl + 7) / 8;

    bl = ctx->cipher->block_size;

    if (inl <= 0) {
       *outl = 0;
       return inl == 0;
    }
    if (is_partially_overlapping(out + ctx->buf_len, in, cmpl)) {
       EVPerr(EVP_F_EVP_ENCRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING);
       return 0;
    }

    if (ctx->buf_len == 0 && (inl & (ctx->block_mask)) == 0) {
       if (altera_stub_aes_cipher_inner(ctx, out, in, inl, 0)) {
           *outl = inl;
           return 1;
       } else {
           *outl = 0;
           return 0;
       }
    }
    i = ctx->buf_len;
    OPENSSL_assert(bl <= (int)sizeof(ctx->buf));
    if (i != 0) {
       if (bl - i > inl) {
           memcpy(&(ctx->buf[i]), in, inl);
           ctx->buf_len += inl;
           *outl = 0;
           return 1;
       } else {
           j = bl - i;
           memcpy(&(ctx->buf[i]), in, j);
           inl -= j;
           in += j;
           if (!altera_stub_aes_cipher_inner(ctx, out, ctx->buf, bl, 0))
               return 0;
           out += bl;
           *outl = bl;
       }
    } else
       *outl = 0;
    i = inl & (bl - 1);
    inl -= i;
    if (inl > 0) {
       if (altera_stub_aes_cipher_inner(ctx, out, in, inl, 0))
           return 0;
       *outl += inl;
    }

    if (i != 0)
       memcpy(ctx->buf, &(in[inl]), i);
    ctx->buf_len = i;
    return 1;
}

int altera_stub_aes_encrypt_final(EVP_CIPHER_CTX *ctx,
                                  unsigned char *out, int *outl) {
    int n, ret;
    unsigned int i, b, bl;

    b = ctx->cipher->block_size;
    OPENSSL_assert(b <= sizeof ctx->buf);
    if (b == 1) {
      *outl = 0;
      return 1;
    }
    bl = ctx->buf_len;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
      if (bl) {
          EVPerr(EVP_F_EVP_ENCRYPTFINAL_EX,
                 EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
          return 0;
      }
      *outl = 0;
      return 1;
    }

    n = b - bl;
    for (i = bl; i < b; i++)
      ctx->buf[i] = n;
    ret = altera_stub_aes_cipher_inner(ctx, out, ctx->buf, b, 1);

    if (ret)
      *outl = b;

    return ret;
}

int altera_stub_aes_decrypt_update(EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl,
                                   const unsigned char *in, int inl) {
    int fix_len, cmpl = inl;
    unsigned int b;

    b = ctx->cipher->block_size;

    if (EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS))
       cmpl = (cmpl + 7) / 8;

    if (inl <= 0) {
       *outl = 0;
       return inl == 0;
    }

    if (ctx->flags & EVP_CIPH_NO_PADDING)
       return altera_stub_aes_encrypt_update(ctx, out, outl, in, inl);

    OPENSSL_assert(b <= sizeof ctx->final);

    if (ctx->final_used) {
       /* see comment about PTRDIFF_T comparison above */
       if (((PTRDIFF_T)out == (PTRDIFF_T)in)
           || is_partially_overlapping(out, in, b)) {
           EVPerr(EVP_F_EVP_DECRYPTUPDATE, EVP_R_PARTIALLY_OVERLAPPING);
           return 0;
       }
       memcpy(out, ctx->final, b);
       out += b;
       fix_len = 1;
    } else
       fix_len = 0;

    if (!altera_stub_aes_encrypt_update(ctx, out, outl, in, inl))
       return 0;

    /*
    * if we have 'decrypted' a multiple of block size, make sure we have a
    * copy of this last block
    */
    if (b > 1 && !ctx->buf_len) {
       *outl -= b;
       ctx->final_used = 1;
       memcpy(ctx->final, &out[*outl], b);
    } else
       ctx->final_used = 0;

    if (fix_len)
       *outl += b;

    return 1;
}

int altera_stub_aes_decrypt_final(EVP_CIPHER_CTX *ctx,
                                  unsigned char *out, int *outl) {
    int i, n;
    unsigned int b;
    *outl = 0;

    b = ctx->cipher->block_size;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
      if (ctx->buf_len) {
          EVPerr(EVP_F_EVP_DECRYPTFINAL_EX,
                 EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
          return 0;
      }
      *outl = 0;
      return 1;
    }
    if (b > 1) {
      if (ctx->buf_len || !ctx->final_used) {
          EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_WRONG_FINAL_BLOCK_LENGTH);
          return (0);
      }
      OPENSSL_assert(b <= sizeof ctx->final);

      /*
       * The following assumes that the ciphertext has been authenticated.
       * Otherwise it provides a padding oracle.
       */
      n = ctx->final[b - 1];
      if (n == 0 || n > (int)b) {
          EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT);
          return (0);
      }
      for (i = 0; i < n; i++) {
          if (ctx->final[--b] != n) {
              EVPerr(EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT);
              return (0);
          }
      }
      n = ctx->cipher->block_size - n;
      for (i = 0; i < n; i++)
          out[i] = ctx->final[i];
      *outl = n;
    } else
      *outl = 0;
    return (1);
}


int altera_stub_aes_cipher_outer(EVP_CIPHER_CTX *ctx,
                           unsigned char *out,
                           const unsigned char *in,
                           size_t inl) \
    //GUARD_DECORATOR(altera_stub_aes_mutex,
    {
        EVP_OPENCL_AES_KEY *data = EVP_CIPHER_CTX_get_cipher_data(ctx);
        int is_final = (in == NULL) && (inl == 0);
        int is_enc = data->enc;

        int processed_bytes = 0;
        if (is_final) {
            if (is_enc) {
                if (!altera_stub_aes_encrypt_final(ctx, out, &processed_bytes)) return -1;
            } else {
                if (!altera_stub_aes_decrypt_final(ctx, out, &processed_bytes)) return -1;
            }
        } else {
            if (is_enc) {
                if (!altera_stub_aes_encrypt_update(ctx, out, &processed_bytes, in, inl)) return -1;
            } else {
                if (!altera_stub_aes_decrypt_update(ctx, out, &processed_bytes, in, inl)) return -1;
            }
        }

        return processed_bytes;
    }//)
