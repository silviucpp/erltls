#ifndef ERLTLS_C_SRC_ERLTLS_NIF_H_
#define ERLTLS_C_SRC_ERLTLS_NIF_H_

#include "erl_nif.h"

struct atoms
{
    ERL_NIF_TERM atomOk;
    ERL_NIF_TERM atomError;
    ERL_NIF_TERM atomTrue;
    ERL_NIF_TERM atomFalse;
    ERL_NIF_TERM atomSslWrite;
    ERL_NIF_TERM atomSslNotStarted;
};

struct erltls_data
{
    ErlNifResourceType* res_ssl_ctx;
    ErlNifResourceType* res_ssl_sock;
};

extern atoms ATOMS;

#endif
