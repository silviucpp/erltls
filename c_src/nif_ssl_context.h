#ifndef C_SRC_NIF_SSL_CONTEXT_H_
#define C_SRC_NIF_SSL_CONTEXT_H_

#include "erl_nif.h"

#include <openssl/ssl.h>

struct erltls_data;

ERL_NIF_TERM enif_ssl_new_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM enif_ciphers(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM enif_openssl_version(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

void enif_ssl_ctx_free(ErlNifEnv* env, void* obj);

SSL_CTX* get_context(ErlNifEnv* env, erltls_data* data, ERL_NIF_TERM term);

#endif  // C_SRC_NIF_SSL_CONTEXT_H_
