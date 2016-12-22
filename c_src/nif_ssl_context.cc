#include "nif_ssl_context.h"
#include "tlsmanager.h"
#include "erltls_nif.h"
#include "nif_utils.h"
#include "macros.h"

#include <memory>

static const char kErrorFailedToCreateContext[]    = "failed to create context";
static const char kErrorFailedToAllocNifContext[]  = "failed to alloc enif_ssl_ctx";

struct enif_ssl_ctx
{
    SSL_CTX* ctx;
};

bool parse_context_props(ErlNifEnv* env, ERL_NIF_TERM list, ContextProperties* props)
{
    ERL_NIF_TERM head;
    const ERL_NIF_TERM *items;
    int arity;
    
    while(enif_get_list_cell(env, list, &head, &list))
    {
        if(!enif_get_tuple(env, head, &arity, &items) || arity != 2)
            return false;
        
        ERL_NIF_TERM key = items[0];
        ERL_NIF_TERM value = items[1];
        
        if(enif_is_identical(key, ATOMS.atomCtxCertfile))
            get_string(env, value, &props->cert_file);
        else if(enif_is_identical(key, ATOMS.atomCtxCacerts))
            get_string(env, value, &props->ca_file);
        else if(enif_is_identical(key, ATOMS.atomCtxCiphers))
            get_string(env, value, &props->ciphers);
        else if(enif_is_identical(key, ATOMS.atomCtxDhfile))
            get_string(env, value, &props->dh_file);
    }
    
    return true;
}

ERL_NIF_TERM enif_ssl_new_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);
    
    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));
    
    ContextProperties props;
    
    if(!parse_context_props(env, argv[0], &props))
        return make_error(env, ATOMS.atomBadArg);
    
    SSL_CTX* ctx = TlsManager::CreateContext(props);
    
    if(!ctx)
        return make_error(env, kErrorFailedToCreateContext);
    
    enif_ssl_ctx *nif_ctx = static_cast<enif_ssl_ctx*>(enif_alloc_resource(data->res_ssl_ctx, sizeof(enif_ssl_ctx)));
    
    if(nif_ctx == NULL)
    {
        SSL_CTX_free(ctx);
        return make_error(env, kErrorFailedToAllocNifContext);
    }
    
    nif_ctx->ctx = ctx;
    ERL_NIF_TERM term = enif_make_resource(env, nif_ctx);
    enif_release_resource(nif_ctx);
    return enif_make_tuple2(env, ATOMS.atomOk, term);
}

ERL_NIF_TERM enif_ciphers(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);

    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));

    SSL_CTX* ctx = get_context(env, data, argv[0]);

    if(!ctx)
        return make_badarg(env);

    scoped_ptr(ssl, SSL, SSL_new(ctx), SSL_free);

    STACK_OF(SSL_CIPHER) *stack = SSL_get_ciphers(ssl.get());

    if(!stack)
        return enif_make_list(env, 0);

    int ciphers_count = sk_SSL_CIPHER_num(stack);
    ERL_NIF_TERM nif_items[ciphers_count];

    for (int i = 0; i < ciphers_count; i++)
    {
        const char* cipher_name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value (stack, i));
        size_t cipher_length = strlen(cipher_name);
        nif_items[i] = make_binary(env, reinterpret_cast<const uint8_t*>(cipher_name), cipher_length);
    }

    return enif_make_list_from_array(env, nif_items, static_cast<unsigned>(ciphers_count));
}

void enif_ssl_ctx_free(ErlNifEnv* env, void* obj)
{
    UNUSED(env);
    
    enif_ssl_ctx *data = static_cast<enif_ssl_ctx*>(obj);
    
    if(data->ctx != NULL)
        SSL_CTX_free(data->ctx);
}

SSL_CTX* get_context(ErlNifEnv* env, erltls_data* data, ERL_NIF_TERM term)
{
    enif_ssl_ctx* ctx = NULL;
    
    if(!enif_get_resource(env, term, data->res_ssl_ctx, (void**) &ctx))
        return NULL;
    
    return ctx->ctx;
}
