#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/crypto.h>

#include "e_altera_stub_err.c"

/* Engine Id and Name */
static const char *engine_altera_stub_id = "altera_stub";
static const char *engine_altera_stub_name = "Altera stub engine, work in progress";


/* Engine Lifetime functions */
static int altera_stub_destroy(ENGINE *e);
static int altera_stub_init(ENGINE *e);
static int altera_stub_finish(ENGINE *e);
void ENGINE_load_altera_stub(void);




static int bind_altera_stub(ENGINE *e)
{
    /* Ensure the ossltest error handling is set up */
    ERR_load_ALTERASTUB_strings();

    if (!ENGINE_set_id(e, engine_altera_stub_id)
        || !ENGINE_set_name(e, engine_altera_stub_name)
        //|| !ENGINE_set_digests(e, ossltest_digests)
        //|| !ENGINE_set_ciphers(e, ossltest_ciphers)
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
    // opencl initialization here
    return 1;
}


static int altera_stub_finish(ENGINE *e)
{
    return 1;
}


static int altera_stub_destroy(ENGINE *e)
{
    //destroy_digests();
    //destroy_ciphers();
    // opencl de-initialization here
    ERR_unload_ALTERASTUB_strings();
    return 1;
}
