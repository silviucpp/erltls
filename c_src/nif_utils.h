#ifndef ERLTLS_C_SRC_NIF_UTILS_H_
#define ERLTLS_C_SRC_NIF_UTILS_H_

#include "erl_nif.h"
#include <string>
#include <stdint.h>

ERL_NIF_TERM make_atom(ErlNifEnv* env, const char* name);
ERL_NIF_TERM make_error(ErlNifEnv* env, const char* error);
ERL_NIF_TERM make_error(ErlNifEnv* env, ERL_NIF_TERM term);
ERL_NIF_TERM make_binary(ErlNifEnv* env, const uint8_t* buff, size_t length);
ERL_NIF_TERM make_ok_result(ErlNifEnv* env, ERL_NIF_TERM term);

bool get_bstring(ErlNifEnv* env, ERL_NIF_TERM term, ErlNifBinary* bin);
bool get_string(ErlNifEnv *env, ERL_NIF_TERM term, std::string* var);

#endif
