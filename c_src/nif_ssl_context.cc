#include "nif_ssl_context.h"
#include "tlsmanager.h"
#include "erltls_nif.h"
#include "nif_utils.h"
#include "macros.h"

static const char kErrorFailedToCreateContext[]    = "failed to create context";
static const char kErrorFailedToAllocNifContext[]  = "failed to alloc enif_ssl_ctx";

struct enif_ssl_ctx
{
    SSL_CTX* ctx;
};

ERL_NIF_TERM enif_ssl_ctx_new(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);
    
    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));
    
    std::string cert_file;
    std::string ciphers;
    std::string dh_file;
    std::string ca_file;

    bool has_cert_file = get_string(env, argv[0], &cert_file);
    bool has_ciphers = get_string(env, argv[1], &ciphers);
    bool has_dh_file = get_string(env, argv[2], &dh_file);
    bool has_ca_file = get_string(env, argv[3], &ca_file);
    
    const char* cert_file_buff = has_cert_file ? cert_file.c_str() : NULL;
    const char* ciphers_buff = has_ciphers ? ciphers.c_str() : NULL;
    const char* dh_file_buff = has_dh_file ? dh_file.c_str() : NULL;
    const char* ca_file_buff = has_ca_file ? ca_file.c_str() : NULL;
    
    SSL_CTX* ctx = TlsManager::CreateContext(cert_file_buff, ciphers_buff, dh_file_buff, ca_file_buff);
    
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
