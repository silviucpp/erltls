#include "nif_ssl_context.h"
#include "tlsmanager.h"
#include "erltls_nif.h"
#include "nif_utils.h"
#include "macros.h"

#include <memory>
#include <vector>
#include <string.h>

static const char kErrorFailedToCreateContext[]    = "failed to create context";
static const char kErrorFailedToAllocNifContext[]  = "failed to alloc enif_ssl_ctx";

struct enif_ssl_ctx
{
    SSL_CTX* ctx;
};

ERL_NIF_TERM parse_context_props(ErlNifEnv* env, ERL_NIF_TERM list, ContextProperties* props)
{
    ERL_NIF_TERM head;
    const ERL_NIF_TERM *items;
    int arity;

    while(enif_get_list_cell(env, list, &head, &list))
    {
        if(!enif_get_tuple(env, head, &arity, &items) || arity != 2)
            return make_bad_options(env, head);

        ERL_NIF_TERM key = items[0];
        ERL_NIF_TERM value = items[1];

        if(enif_is_identical(key, ATOMS.atomCtxCertfile))
        {
            if(!get_string(env, value, &props->certfile))
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxCaCertFile))
        {
            if(!get_string(env, value, &props->ca_certfile))
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxKeyfile))
        {
            if(!get_string(env, value, &props->keyfile))
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxPassword))
        {
            if(!get_string(env, value, &props->password))
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxCiphers))
        {
            if(!get_string(env, value, &props->ciphers))
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxDhfile))
        {
            if(!get_string(env, value, &props->dh_file))
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxReuseSessionsTtl))
        {
            if(!enif_get_uint(env, value, &props->reuse_sessions_ttl_sec))
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxUseSessionTicket))
        {
            if(enif_is_tuple(env, value))
            {
                const ERL_NIF_TERM *ticket_items;

                if(!enif_get_tuple(env, value, &arity, &ticket_items) || arity != 2)
                    return make_bad_options(env, head);

                if(!get_boolean(ticket_items[0], &props->use_session_ticket))
                    return make_bad_options(env, head);

                if(!get_string(env, ticket_items[1], &props->session_ticket_skey))
                    return make_bad_options(env, head);
            }
            else
            {
                if(!get_boolean(value, &props->use_session_ticket))
                    return make_bad_options(env, head);
            }
        }
        else if(enif_is_identical(key, ATOMS.atomCtxFailIfNoPeerCert))
        {
            if(!get_boolean(value, &props->fail_if_no_peer_cert))
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxDepth))
        {
            if(!enif_get_int(env, value, &props->verify_depth))
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxVerify))
        {
            if(enif_is_identical(value, ATOMS.atomVerifyNone))
                props->verify_mode = VERIFY_NONE;
            else if(enif_is_identical(value, ATOMS.atomVerifyPeer))
                props->verify_mode = VERIFY_PEER;
            else
                return make_bad_options(env, head);
        }
        else if(enif_is_identical(key, ATOMS.atomCtxTlsProtocol))
        {
            if(enif_is_identical(value, ATOMS.atomSSLMethodTLSv1_2))
                props->tls_proto = TLSv1_2_method();
            else if(enif_is_identical(value, ATOMS.atomSSLMethodTLSv1_1))
                props->tls_proto = TLSv1_1_method();
            else if(enif_is_identical(value, ATOMS.atomSSLMethodTLSv1))
                props->tls_proto = TLSv1_method();
            else if(enif_is_identical(value, ATOMS.atomSSLMethodSSLv3))
#ifndef OPENSSL_IS_BORINGSSL
                props->tls_proto = SSLv3_method();
#else
                return make_bad_options(env, head);
#endif
            else if(enif_is_identical(value, ATOMS.atomSSLMethodDTLSv1_2))
                props->tls_proto = DTLSv1_2_method();
            else if(enif_is_identical(value, ATOMS.atomSSLMethodDTLSv1))
                props->tls_proto = DTLSv1_method();
            else
                return make_bad_options(env, head);
        }
    }

    return ATOMS.atomOk;
}

ERL_NIF_TERM enif_ssl_new_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);

    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));

    ContextProperties props;

    ERL_NIF_TERM parse_result = parse_context_props(env, argv[0], &props);

    if(!enif_is_identical(parse_result, ATOMS.atomOk))
        return parse_result;

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

    std::vector<ERL_NIF_TERM> nif_items;
    nif_items.reserve(ciphers_count);

    for (int i = 0; i < ciphers_count; i++)
    {
        const char* cipher_name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value (stack, i));
        size_t cipher_length = strlen(cipher_name);
        nif_items.push_back(make_binary(env, reinterpret_cast<const uint8_t*>(cipher_name), cipher_length));
    }

    return enif_make_list_from_array(env, nif_items.data(), nif_items.size());
}

ERL_NIF_TERM enif_openssl_version(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);
    UNUSED(argv);
    return TlsManager::GetOpenSSLVersion(env);
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

    if(!enif_get_resource(env, term, data->res_ssl_ctx, reinterpret_cast<void**>(&ctx)))
        return NULL;

    return ctx->ctx;
}
