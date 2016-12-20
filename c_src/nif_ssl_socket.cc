#include "nif_ssl_socket.h"
#include "nif_ssl_context.h"
#include "tlssocket.h"
#include "erltls_nif.h"
#include "macros.h"
#include "nif_utils.h"

struct enif_ssl_socket
{
    TlsSocket* socket;
};

ERL_NIF_TERM enif_ssl_socket_new(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);
    
    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));
    
    int role;
    long flags;
    SSL_CTX* ctx = get_context(env, data, argv[0]);
    
    if(!ctx)
        return make_error(env, "failed to get context");

    if(!enif_get_int(env, argv[1], &role))
        return make_error(env, "failed to get ssl role");
    
    if(!enif_get_long(env, argv[2], &flags))
        return make_error(env, "failed to get flags");
    
    std::unique_ptr<enif_ssl_socket, decltype(&enif_release_resource)> nif_socket(static_cast<enif_ssl_socket*>(enif_alloc_resource(data->res_ssl_sock, sizeof(enif_ssl_socket))), &enif_release_resource);
    
    if(nif_socket.get() == NULL)
        return make_error(env, "failed to alloc enif_ssl_socket");
    
    TlsSocket* socket = new TlsSocket();
    
    if(socket == NULL)
        return make_error(env, "failed to alloc ssl socket");
    
    if(!socket->Init(ctx, static_cast<TlsSocket::kSslRole>(role), flags))
        return make_error(env, "failed to init ssl socket");
    
    nif_socket->socket = socket;
    
    ERL_NIF_TERM term = enif_make_resource(env, nif_socket.get());
    return enif_make_tuple2(env, ATOMS.atomOk, term);
}

void enif_ssl_socket_free(ErlNifEnv* env, void* obj)
{
    UNUSED(env);
    
    enif_ssl_socket *data = static_cast<enif_ssl_socket*>(obj);
    
    if(data->socket != NULL)
        delete data->socket;
}

ERL_NIF_TERM enif_ssl_socket_handshake(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);
    
    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));
    
    enif_ssl_socket* wp = NULL;
    
    if(!enif_get_resource(env, argv[0], data->res_ssl_sock, (void**) &wp))
        return make_error(env, "failed to get socket");
        
    return wp->socket->Handshake(env);
}

ERL_NIF_TERM enif_ssl_socket_send_pending(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);
    
    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));
    
    enif_ssl_socket* wp = NULL;
    
    if(!enif_get_resource(env, argv[0], data->res_ssl_sock, (void**) &wp))
        return make_error(env, "failed to get socket");
    
    return wp->socket->SendPending(env);
}

ERL_NIF_TERM enif_ssl_socket_feed_data(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);
    
    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));
    
    enif_ssl_socket* wp = NULL;
    ErlNifBinary bin;
    
    if(!enif_get_resource(env, argv[0], data->res_ssl_sock, (void**) &wp))
        return make_error(env, "failed to get socket");
    
    if(!get_bstring(env, argv[1], &bin))
        return make_error(env, "failed to get binary data");
    
    return wp->socket->FeedData(env, &bin);
}

ERL_NIF_TERM enif_ssl_socket_send_data(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);
    
    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));
    
    enif_ssl_socket* wp = NULL;
    ErlNifBinary bin;
    
    if(!enif_get_resource(env, argv[0], data->res_ssl_sock, (void**) &wp))
        return make_error(env, "failed to get socket");
    
    if(!get_bstring(env, argv[1], &bin))
        return make_error(env, "failed to get binary data");
    
    return wp->socket->SendData(env, &bin);
}

ERL_NIF_TERM enif_ssl_socket_shutdown(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    UNUSED(argc);
    
    erltls_data* data = static_cast<erltls_data*>(enif_priv_data(env));
    enif_ssl_socket* wp = NULL;
    
    if(!enif_get_resource(env, argv[0], data->res_ssl_sock, (void**) &wp))
        return make_error(env, "failed to get socket");
    
    return wp->socket->Shutdown(env);
}
