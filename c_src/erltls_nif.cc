#include "erltls_nif.h"
#include "nif_utils.h"
#include "macros.h"
#include "nif_ssl_context.h"
#include "nif_ssl_socket.h"
#include "tlsmanager.h"

const char kAtomOk[] = "ok";
const char kAtomTrue[] = "true";
const char kAtomFalse[] = "false";
const char kAtomError[] = "error";
const char kAtomBadArg[] = "badarg";
const char kAtomOptions[] = "options";

const char kAtomSllNotStarted[] = "ssl_not_started";

const char kAtomCtxCertfile[] = "certfile";
const char kAtomCtxDhfile[] = "dhfile";
const char kAtomCtxCacerts[] = "cacerts";
const char kAtomCtxCiphers[] = "ciphers";
const char kAtomCtxReuseSessionsTtl[] = "reuse_sessions_ttl";
const char kAtomCtxUseSessionTicket[] = "use_session_ticket";

atoms ATOMS;

void open_resources(ErlNifEnv* env, erltls_data* data)
{
    ErlNifResourceFlags flags =  static_cast<ErlNifResourceFlags>(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);
    data->res_ssl_ctx = enif_open_resource_type(env, NULL, "enif_ssl_ctx", enif_ssl_ctx_free, flags, NULL);
    data->res_ssl_sock = enif_open_resource_type(env, NULL, "enif_ssl_sock", enif_ssl_socket_free, flags, NULL);
}

int on_nif_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    UNUSED(load_info);
    
    TlsManager::InitOpenSSL();
    
    ATOMS.atomOk = make_atom(env, kAtomOk);
    ATOMS.atomTrue = make_atom(env, kAtomTrue);
    ATOMS.atomFalse = make_atom(env, kAtomFalse);
    ATOMS.atomError = make_atom(env, kAtomError);
    ATOMS.atomOptions = make_atom(env, kAtomOptions);
    ATOMS.atomBadArg = make_atom(env, kAtomBadArg);

    ATOMS.atomSslNotStarted = make_atom(env, kAtomSllNotStarted);

    ATOMS.atomCtxCertfile = make_atom(env, kAtomCtxCertfile);
    ATOMS.atomCtxDhfile = make_atom(env, kAtomCtxDhfile);
    ATOMS.atomCtxCacerts = make_atom(env, kAtomCtxCacerts);
    ATOMS.atomCtxCiphers = make_atom(env, kAtomCtxCiphers);
    ATOMS.atomCtxReuseSessionsTtl = make_atom(env, kAtomCtxReuseSessionsTtl);
    ATOMS.atomCtxUseSessionTicket = make_atom(env, kAtomCtxUseSessionTicket);

    erltls_data* data = static_cast<erltls_data*>(enif_alloc(sizeof(erltls_data)));
    open_resources(env, data);
    
    *priv_data = data;
    return 0;
}

void on_nif_unload(ErlNifEnv* env, void* priv_data)
{
    UNUSED(env);
    erltls_data* data = static_cast<erltls_data*>(priv_data);
    enif_free(data);
    TlsManager::CleanupOpenSSL();
}

int on_nif_upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM info)
{
    UNUSED(old_priv);
    UNUSED(info);
    
    erltls_data* data = static_cast<erltls_data*>(enif_alloc(sizeof(erltls_data)));
    open_resources(env, data);
    
    *priv = data;
    return 0;
}

static ErlNifFunc nif_funcs[] =
{    
    {"new_context", 1, enif_ssl_new_context},
    {"ciphers", 1, enif_ciphers},
    {"ssl_new", 4, enif_ssl_socket_new},
    {"ssl_handshake", 1, enif_ssl_socket_handshake},
    {"ssl_send_pending", 1, enif_ssl_socket_send_pending},
    {"ssl_feed_data", 2, enif_ssl_socket_feed_data},
    {"ssl_send_data", 2, enif_ssl_socket_send_data},
    {"ssl_get_session_asn1", 1, enif_ssl_socket_get_session_ans1},
    {"ssl_session_reused", 1, enif_ssl_socket_session_reused},
    {"ssl_shutdown", 1, enif_ssl_socket_shutdown}
};

ERL_NIF_INIT(erltls_nif, nif_funcs, on_nif_load, NULL, on_nif_upgrade, on_nif_unload)
