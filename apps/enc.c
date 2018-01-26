/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_COMP
# include <openssl/comp.h>
#endif
#include <ctype.h>

#include "perf_counter_portable.h"

#undef SIZE
#undef BSIZE
#define SIZE    (512)
#define BSIZE   (8*1024)

#define DEFAULT_NUM_PARALLEL_WORKERS 4

static int set_hex(char *in, unsigned char *out, int size);
static void show_ciphers(const OBJ_NAME *name, void *bio_);
static void *enc_write_worker(void *param);

struct doall_enc_ciphers {
    BIO *bio;
    int n;
};

struct enc_worker_param {
    unsigned char *buff;
    BIO *wbio;
    BIO *first_stage_model;
    int inl;
    int err;
    long blockid;
    EVP_CIPHER_CTX *ctx;
    PerfCounter *perf_counter;
};
static long parallel_last_written_block;
pthread_mutex_t parallel_condition_mutex;
pthread_cond_t  parallel_condition_cond;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_LIST,
    OPT_E, OPT_IN, OPT_OUT, OPT_PASS, OPT_ENGINE, OPT_D, OPT_P, OPT_V, OPT_PARALLEL,
    OPT_NOPAD, OPT_SALT, OPT_NOSALT, OPT_DEBUG, OPT_UPPER_P, OPT_UPPER_A,
    OPT_A, OPT_Z, OPT_BUFSIZE, OPT_K, OPT_KFILE, OPT_UPPER_K, OPT_NONE,
    OPT_UPPER_S, OPT_IV, OPT_MD, OPT_CIPHER
} OPTION_CHOICE;

const OPTIONS enc_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"ciphers", OPT_LIST, '-', "List ciphers"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"pass", OPT_PASS, 's', "Passphrase source"},
    {"e", OPT_E, '-', "Encrypt"},
    {"d", OPT_D, '-', "Decrypt"},
    {"p", OPT_P, '-', "Print the iv/key"},
    {"P", OPT_UPPER_P, '-', "Print the iv/key and exit"},
    {"v", OPT_V, '-', "Verbose output"},
    {"parallel", OPT_PARALLEL, '-', "Run the cipher in multiple parallel instances"},
    {"nopad", OPT_NOPAD, '-', "Disable standard block padding"},
    {"salt", OPT_SALT, '-', "Use salt in the KDF (default)"},
    {"nosalt", OPT_NOSALT, '-', "Do not use salt in the KDF"},
    {"debug", OPT_DEBUG, '-', "Print debug info"},
    {"a", OPT_A, '-', "Base64 encode/decode, depending on encryption flag"},
    {"base64", OPT_A, '-', "Same as option -a"},
    {"A", OPT_UPPER_A, '-',
     "Used with -[base64|a] to specify base64 buffer as a single line"},
    {"bufsize", OPT_BUFSIZE, 's', "Buffer size"},
    {"k", OPT_K, 's', "Passphrase"},
    {"kfile", OPT_KFILE, '<', "Read passphrase from file"},
    {"K", OPT_UPPER_K, 's', "Raw key, in hex"},
    {"S", OPT_UPPER_S, 's', "Salt, in hex"},
    {"iv", OPT_IV, 's', "IV in hex"},
    {"md", OPT_MD, 's', "Use specified digest to create a key from the passphrase"},
    {"none", OPT_NONE, '-', "Don't encrypt"},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
#ifdef ZLIB
    {"z", OPT_Z, '-', "Use zlib as the 'encryption'"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int enc_main(int argc, char **argv)
{
    static char buf[128];
    static const char magic[] = "Salted__";
    ENGINE *e = NULL;
    BIO *in = NULL, *out = NULL, *b64 = NULL, *benc = NULL, *rbio =
        NULL, *wbio = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL, *c;
    const EVP_MD *dgst = NULL;
    char *hkey = NULL, *hiv = NULL, *hsalt = NULL, *p;
    char *infile = NULL, *outfile = NULL, *prog;
    char *str = NULL, *passarg = NULL, *pass = NULL, *strbuf = NULL;
    char mbuf[sizeof magic - 1];
    OPTION_CHOICE o;
    int bsize = BSIZE, verbose = 0, debug = 0, olb64 = 0, nosalt = 0;
    int enc = 1, printkey = 0, i, k;
    int base64 = 0, informat = FORMAT_BINARY, outformat = FORMAT_BINARY;
    int ret = 1, inl, nopad = 0;
    int parallel = 0, num_parallel_workers = 1, wc, pwc;
    pthread_t *workers;
    struct enc_worker_param *worker_params;
    long para_block_id;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char **buff = NULL, salt[PKCS5_SALT_LEN];
    long n;
    struct doall_enc_ciphers dec;
#ifdef ZLIB
    int do_zlib = 0;
    BIO *bzl = NULL;
#endif

    PerfCounter *perf_counter = NULL;

    /* first check the program name */
    prog = opt_progname(argv[0]);
    if (strcmp(prog, "base64") == 0) {
        base64 = 1;
#ifdef ZLIB
    } else if (strcmp(prog, "zlib") == 0) {
        do_zlib = 1;
#endif
    } else {
        cipher = EVP_get_cipherbyname(prog);
        if (cipher == NULL && strcmp(prog, "enc") != 0) {
            BIO_printf(bio_err, "%s is not a known cipher\n", prog);
            goto end;
        }
    }

    prog = opt_init(argc, argv, enc_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(enc_options);
            ret = 0;
            goto end;
        case OPT_LIST:
            BIO_printf(bio_out, "Supported ciphers:\n");
            dec.bio = bio_out;
            dec.n = 0;
            OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH,
                                   show_ciphers, &dec);
            BIO_printf(bio_out, "\n");
            ret = 0;
            goto end;
        case OPT_E:
            enc = 1;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASS:
            passarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_D:
            enc = 0;
            break;
        case OPT_P:
            printkey = 1;
            break;
        case OPT_V:
            verbose = 1;
            break;
        case OPT_NOPAD:
            nopad = 1;
            break;
        case OPT_SALT:
            nosalt = 0;
            break;
        case OPT_NOSALT:
            nosalt = 1;
            break;
        case OPT_DEBUG:
            debug = 1;
            break;
        case OPT_UPPER_P:
            printkey = 2;
            break;
        case OPT_UPPER_A:
            olb64 = 1;
            break;
        case OPT_A:
            base64 = 1;
            break;
        case OPT_PARALLEL:
            parallel = 1;
            num_parallel_workers = DEFAULT_NUM_PARALLEL_WORKERS;
            break;
        case OPT_Z:
#ifdef ZLIB
            do_zlib = 1;
#endif
            break;
        case OPT_BUFSIZE:
            p = opt_arg();
            i = (int)strlen(p) - 1;
            k = i >= 1 && p[i] == 'k';
            if (k)
                p[i] = '\0';
            if (!opt_long(opt_arg(), &n)
                    || n < 0 || (k && n >= LONG_MAX / 1024))
                goto opthelp;
            if (k)
                n *= 1024;
            bsize = (int)n;
            break;
        case OPT_K:
            str = opt_arg();
            break;
        case OPT_KFILE:
            in = bio_open_default(opt_arg(), 'r', FORMAT_TEXT);
            if (in == NULL)
                goto opthelp;
            i = BIO_gets(in, buf, sizeof buf);
            BIO_free(in);
            in = NULL;
            if (i <= 0) {
                BIO_printf(bio_err,
                           "%s Can't read key from %s\n", prog, opt_arg());
                goto opthelp;
            }
            while (--i > 0 && (buf[i] == '\r' || buf[i] == '\n'))
                buf[i] = '\0';
            if (i <= 0) {
                BIO_printf(bio_err, "%s: zero length password\n", prog);
                goto opthelp;
            }
            str = buf;
            break;
        case OPT_UPPER_K:
            hkey = opt_arg();
            break;
        case OPT_UPPER_S:
            hsalt = opt_arg();
            break;
        case OPT_IV:
            hiv = opt_arg();
            break;
        case OPT_MD:
            if (!opt_md(opt_arg(), &dgst))
                goto opthelp;
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &c))
                goto opthelp;
            cipher = c;
            break;
        case OPT_NONE:
            cipher = NULL;
            break;
        }
    }

    if (cipher && EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
        BIO_printf(bio_err, "%s: AEAD ciphers not supported\n", prog);
        goto end;
    }

    if (cipher && (EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)) {
        BIO_printf(bio_err, "%s XTS ciphers not supported\n", prog);
        goto end;
    }

    if (dgst == NULL)
        dgst = EVP_sha256();

    /* It must be large enough for a base64 encoded line */
    if (base64 && bsize < 80)
        bsize = 80;
    if (verbose)
        BIO_printf(bio_err, "bufsize=%d\n", bsize);

#ifdef ZLIB
    if (!do_zlib)
#endif
        if (base64) {
            if (enc)
                outformat = FORMAT_BASE64;
            else
                informat = FORMAT_BASE64;
        }

    strbuf = app_malloc(SIZE, "strbuf");
    buff = app_malloc(num_parallel_workers * sizeof(char*), "evp buffer list");
    for (wc = 0; wc < num_parallel_workers; wc++) {
        buff[wc] = app_malloc(EVP_ENCODE_LENGTH(bsize), "evp buffer");
    }

    perf_counter = PerfCounter_create_auto();

    if (infile == NULL) {
        in = dup_bio_in(informat);
    } else {
        in = bio_open_default(infile, 'r', informat);
    }
    if (in == NULL)
        goto end;

    if (str == NULL && passarg != NULL) {
        if (!app_passwd(passarg, NULL, &pass, NULL)) {
            BIO_printf(bio_err, "Error getting password\n");
            goto end;
        }
        str = pass;
    }

    if ((str == NULL) && (cipher != NULL) && (hkey == NULL)) {
        if (1) {
#ifndef OPENSSL_NO_UI
            for (;;) {
                char prompt[200];

                BIO_snprintf(prompt, sizeof prompt, "enter %s %s password:",
                             OBJ_nid2ln(EVP_CIPHER_nid(cipher)),
                             (enc) ? "encryption" : "decryption");
                strbuf[0] = '\0';
                i = EVP_read_pw_string((char *)strbuf, SIZE, prompt, enc);
                if (i == 0) {
                    if (strbuf[0] == '\0') {
                        ret = 1;
                        goto end;
                    }
                    str = strbuf;
                    break;
                }
                if (i < 0) {
                    BIO_printf(bio_err, "bad password read\n");
                    goto end;
                }
            }
        } else {
#endif
            BIO_printf(bio_err, "password required\n");
            goto end;
        }
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    if (debug) {
        BIO_set_callback(in, BIO_debug_callback);
        BIO_set_callback(out, BIO_debug_callback);
        BIO_set_callback_arg(in, (char *)bio_err);
        BIO_set_callback_arg(out, (char *)bio_err);
    }

    rbio = in;
    wbio = out;

#ifdef ZLIB
    if (do_zlib) {
        if ((bzl = BIO_new(BIO_f_zlib())) == NULL)
            goto end;
        if (debug) {
            BIO_set_callback(bzl, BIO_debug_callback);
            BIO_set_callback_arg(bzl, (char *)bio_err);
        }
        if (enc)
            wbio = BIO_push(bzl, wbio);
        else
            rbio = BIO_push(bzl, rbio);
    }
#endif

    if (base64) {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL)
            goto end;
        if (debug) {
            BIO_set_callback(b64, BIO_debug_callback);
            BIO_set_callback_arg(b64, (char *)bio_err);
        }
        if (olb64)
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        if (enc)
            wbio = BIO_push(b64, wbio);
        else
            rbio = BIO_push(b64, rbio);
    }

    if (cipher != NULL) {
        /*
         * Note that str is NULL if a key was passed on the command line, so
         * we get no salt in that case. Is this a bug?
         */
        if (str != NULL) {
            /*
             * Salt handling: if encrypting generate a salt and write to
             * output BIO. If decrypting read salt from input BIO.
             */
            unsigned char *sptr;
            size_t str_len = strlen(str);

            if (nosalt) {
                sptr = NULL;
            } else {
                if (enc) {
                    if (hsalt) {
                        if (!set_hex(hsalt, salt, sizeof salt)) {
                            BIO_printf(bio_err, "invalid hex salt value\n");
                            goto end;
                        }
                    } else if (RAND_bytes(salt, sizeof salt) <= 0) {
                        goto end;
                    }
                    /*
                     * If -P option then don't bother writing
                     */
                    if ((printkey != 2)
                        && (BIO_write(wbio, magic,
                                      sizeof magic - 1) != sizeof magic - 1
                            || BIO_write(wbio,
                                         (char *)salt,
                                         sizeof salt) != sizeof salt)) {
                        BIO_printf(bio_err, "error writing output file\n");
                        goto end;
                    }
                } else if (BIO_read(rbio, mbuf, sizeof mbuf) != sizeof mbuf
                           || BIO_read(rbio,
                                       (unsigned char *)salt,
                                       sizeof salt) != sizeof salt) {
                    BIO_printf(bio_err, "error reading input file\n");
                    goto end;
                } else if (memcmp(mbuf, magic, sizeof magic - 1)) {
                    BIO_printf(bio_err, "bad magic number\n");
                    goto end;
                }

                sptr = salt;
            }

            if (!EVP_BytesToKey(cipher, dgst, sptr,
                                (unsigned char *)str,
                                str_len, 1, key, iv)) {
                BIO_printf(bio_err, "EVP_BytesToKey failed\n");
                goto end;
            }
            /*
             * zero the complete buffer or the string passed from the command
             * line bug picked up by Larry J. Hughes Jr. <hughes@indiana.edu>
             */
            if (str == strbuf)
                OPENSSL_cleanse(str, SIZE);
            else
                OPENSSL_cleanse(str, str_len);
        }
        if (hiv != NULL) {
            int siz = EVP_CIPHER_iv_length(cipher);
            if (siz == 0) {
                BIO_printf(bio_err, "warning: iv not use by this cipher\n");
            } else if (!set_hex(hiv, iv, sizeof iv)) {
                BIO_printf(bio_err, "invalid hex iv value\n");
                goto end;
            }
        }
        if ((hiv == NULL) && (str == NULL)
            && EVP_CIPHER_iv_length(cipher) != 0) {
            /*
             * No IV was explicitly set and no IV was generated during
             * EVP_BytesToKey. Hence the IV is undefined, making correct
             * decryption impossible.
             */
            BIO_printf(bio_err, "iv undefined\n");
            goto end;
        }
        if ((hkey != NULL) && !set_hex(hkey, key, EVP_CIPHER_key_length(cipher))) {
            BIO_printf(bio_err, "invalid hex key value\n");
            goto end;
        }

        if ((benc = BIO_new(BIO_f_cipher())) == NULL)
            goto end;

        /*
         * Since we may be changing parameters work on the encryption context
         * rather than calling BIO_set_cipher().
         */

        BIO_get_cipher_ctx(benc, &ctx);

        if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc)) {
            BIO_printf(bio_err, "Error setting cipher %s\n",
                       EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

        if (nopad)
            EVP_CIPHER_CTX_set_padding(ctx, 0);

        if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc)) {
            BIO_printf(bio_err, "Error setting cipher %s\n",
                       EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

        if (debug) {
            BIO_set_callback(benc, BIO_debug_callback);
            BIO_set_callback_arg(benc, (char *)bio_err);
        }

        if (printkey) {
            if (!nosalt) {
                printf("salt=");
                for (i = 0; i < (int)sizeof(salt); i++)
                    printf("%02X", salt[i]);
                printf("\n");
            }
            if (EVP_CIPHER_key_length(cipher) > 0) {
                printf("key=");
                for (i = 0; i < EVP_CIPHER_key_length(cipher); i++)
                    printf("%02X", key[i]);
                printf("\n");
            }
            if (EVP_CIPHER_iv_length(cipher) > 0) {
                printf("iv =");
                for (i = 0; i < EVP_CIPHER_iv_length(cipher); i++)
                    printf("%02X", iv[i]);
                printf("\n");
            }
            if (printkey == 2) {
                ret = 0;
                goto end;
            }
        }
    }

    
    PERF_CTR_START(perf_counter);
    if (!parallel) {
        
        /* Only encrypt/decrypt as we write the file */
        if (benc != NULL)
            wbio = BIO_push(benc, wbio);
        
        for (;;) {
            inl = BIO_read(rbio, (char *)buff[0], bsize);
            if (inl <= 0)
                break;
            if (BIO_write(wbio, (char *)buff[0], inl) != inl) {
                BIO_printf(bio_err, "error writing output file\n");
                goto end;
            }
            PERF_CTR_MARK(perf_counter, inl);
        }
        if (!BIO_flush(wbio)) {
            BIO_printf(bio_err, "bad decrypt\n");
            goto end;
        }
    }
    else {
        BIO *first_stage_model = benc;
        
        // prepare worker & param lists
        workers = (pthread_t*) app_malloc(num_parallel_workers * sizeof(pthread_t), "worker list");
        worker_params = (struct enc_worker_param*) app_malloc(num_parallel_workers * sizeof(struct enc_worker_param), "worker param list");
        
        pthread_cond_init(&parallel_condition_cond, NULL);
        pthread_mutex_init(&parallel_condition_mutex, NULL);
        
        para_block_id = 0;
        parallel_last_written_block = -1;
        while (1) {
            wc = para_block_id % num_parallel_workers;  // set the worker counter
            
            if (para_block_id >= num_parallel_workers) { // wait for the previous instance to terminate
                pthread_join(workers[wc], NULL);
                if (worker_params[wc].err) { // handle error in previous instance
                    break;
                }
            }
            // read input normally
            inl = BIO_read(rbio, (char *)buff[wc], bsize);
            if (inl <= 0) {
                break;
            }
            // set the params
            worker_params[wc].wbio = wbio;
            worker_params[wc].first_stage_model = first_stage_model;
            worker_params[wc].buff = buff[wc];
            worker_params[wc].inl = inl;
            worker_params[wc].ctx = ctx;
            worker_params[wc].err = 0;
            worker_params[wc].blockid = para_block_id;
            worker_params[wc].perf_counter = perf_counter;
            pthread_create(workers + wc, NULL, &enc_write_worker, (void*) (worker_params + wc));
            
            para_block_id++;
        }
        
        if (para_block_id >= num_parallel_workers) {
            wc = num_parallel_workers;
        } else {
            wc = para_block_id % num_parallel_workers;
        }
        for (pwc=0; pwc<wc; pwc++) {
            pthread_join(workers[pwc], NULL);
        }
        OPENSSL_free(worker_params);
        OPENSSL_free(workers);
    }

    ret = 0;
    if (verbose) {
        BIO_printf(bio_err, "bytes read   : %8ju\n", BIO_number_read(in));
        BIO_printf(bio_err, "bytes written: %8ju\n", BIO_number_written(out));
    }
 end:
    PERF_CTR_DESTROY(perf_counter);
    ERR_print_errors(bio_err);
    OPENSSL_free(strbuf);
    for (wc = 0; wc < num_parallel_workers; wc++) {
        OPENSSL_free(buff[wc]);
    }
    OPENSSL_free(buff);
    BIO_free(in);
    BIO_free_all(out);
    BIO_free(benc);
    BIO_free(b64);
#ifdef ZLIB
    BIO_free(bzl);
#endif
    release_engine(e);
    OPENSSL_free(pass);
    return (ret);
}

static void *enc_write_worker(void *param) {
    struct enc_worker_param *p = (struct enc_worker_param*) param;
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *benc = BIO_dup_chain(p->first_stage_model);
    BIO *first_stage = BIO_push(benc, mem);
    
    // Encrypt
    fprintf(stderr, "computing block %d\n", p->blockid);
    if (BIO_write(first_stage, (char *)p->buff, p->inl) != p->inl) {
        BIO_printf(bio_err, "error writing temp memory\n");
        p->err = 1;
    }
    
    // wait before committing the results
    fprintf(stderr, "block %d awaiting write\n", p->blockid);
    pthread_mutex_lock(&parallel_condition_mutex);
    while (parallel_last_written_block+1 < p->blockid) {
        pthread_cond_wait(&parallel_condition_cond, &parallel_condition_mutex);
    }
    pthread_mutex_unlock(&parallel_condition_mutex);
    fprintf(stderr, "block %d write unlocked\n", p->blockid);
    
    // Write results
    if (!p->err) {
        char *out_data;
        long outl = BIO_get_mem_data(first_stage, &out_data);
        if (BIO_write(p->wbio, out_data, outl) != outl) {
            BIO_printf(bio_err, "error writing output\n");
            p->err = 1;
        }
    }
    
    // notify all the other threads
    pthread_mutex_lock(&parallel_condition_mutex);
    parallel_last_written_block = p->blockid;
    pthread_mutex_unlock(&parallel_condition_mutex);
    pthread_cond_broadcast(&parallel_condition_cond);
    fprintf(stderr, "block %d broadcasted completion\n", p->blockid);
    
    BIO_free(first_stage);
    PERF_CTR_MARK(p->perf_counter, p->inl);
}

static void show_ciphers(const OBJ_NAME *name, void *arg)
{
    struct doall_enc_ciphers *dec = (struct doall_enc_ciphers *)arg;
    const EVP_CIPHER *cipher;

    if (!islower((unsigned char)*name->name))
        return;

    /* Filter out ciphers that we cannot use */
    cipher = EVP_get_cipherbyname(name->name);
    if (cipher == NULL ||
            (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0 ||
            EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)
        return;

    BIO_printf(dec->bio, "-%-25s", name->name);
    if (++dec->n == 3) {
        BIO_printf(dec->bio, "\n");
        dec->n = 0;
    } else
        BIO_printf(dec->bio, " ");
}

static int set_hex(char *in, unsigned char *out, int size)
{
    int i, n;
    unsigned char j;

    n = strlen(in);
    if (n > (size * 2)) {
        BIO_printf(bio_err, "hex string is too long\n");
        return (0);
    }
    memset(out, 0, size);
    for (i = 0; i < n; i++) {
        j = (unsigned char)*in;
        *(in++) = '\0';
        if (j == 0)
            break;
        if (!isxdigit(j)) {
            BIO_printf(bio_err, "non-hex digit\n");
            return (0);
        }
        j = (unsigned char)OPENSSL_hexchar2int(j);
        if (i & 1)
            out[i / 2] |= j;
        else
            out[i / 2] = (j << 4);
    }
    return (1);
}
