#include "tlssocket.h"
#include "tlsmanager.h"
#include "nif_utils.h"
#include "erltls_nif.h"
#include "bytebuffer.h"

#include <cassert>

//http://roxlu.com/2014/042/using-openssl-with-memory-bios
//https://github.com/deleisha/evt-tls/blob/master/evt_tls.c
//https://github.com/deleisha/evt-tls/blob/master/evt_tls.h

const int kTlsFrameSize = 16*1024;

TlsSocket::TlsSocket() :
    bio_read_(NULL),
    bio_write_(NULL),
    ssl_(NULL)
{
    
}

TlsSocket::~TlsSocket()
{
    if (ssl_)
        SSL_free(ssl_);
}

bool TlsSocket::Init(SSL_CTX* ctx, kSslRole role, long flags)
{
    ssl_ = SSL_new(ctx);
    
    if (flags & kFlagVerifyNone)
        SSL_set_verify(ssl_, SSL_VERIFY_NONE, TlsManager::VerifyCallback);
    
    bio_read_ = BIO_new(BIO_s_mem());
    bio_write_ = BIO_new(BIO_s_mem());
    
    if(!bio_write_ || !bio_read_)
        return false;
    
    SSL_set_bio(ssl_, bio_read_, bio_write_);
    
    int options = SSL_OP_NO_TICKET|SSL_OP_NO_SSLv2;
    
#ifdef SSL_OP_NO_COMPRESSION
    if (flags & kFlagCompressionNone)
        options |= SSL_OP_NO_COMPRESSION;
#endif
    
    if(role == kSslRoleServer)
        options |= SSL_OP_ALL;
    
    if(!SSL_set_options(ssl_, options))
        return false;
    
    if(role == kSslRoleServer)
        SSL_set_accept_state(ssl_);
    else
        SSL_set_connect_state(ssl_);
    
    return true;
}

ERL_NIF_TERM TlsSocket::Shutdown(ErlNifEnv *env)
{
    //Avoid calling SSL_shutdown() if handshake wasn't completed.
    if(!ssl_ || SSL_in_init(ssl_))
        return ATOMS.atomOk;
    
    int r = SSL_shutdown(ssl_);
    
    if(r < 0)
    {
        int error = SSL_get_error(ssl_, r);
        std::string error_str = "SSL_shutdown failed with error: " + std::to_string(error);
        return make_error(env, error_str.c_str());
    }

    return SendPending(env);
}

ERL_NIF_TERM TlsSocket::FeedData(ErlNifEnv *env, const ErlNifBinary* bin)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);
    
    int ret = BIO_write(bio_read_, bin->data, static_cast<int>(bin->size));

    if(ret != static_cast<int>(bin->size))
        return make_error(env, "BIO_write failed");

    if (!SSL_is_init_finished(ssl_))
        return ATOMS.atomOk;
    
    return DoReadOp(env);
}

ERL_NIF_TERM TlsSocket::SendData(ErlNifEnv *env, const ErlNifBinary* bin)
{
    assert(ssl_);
    assert(bin->size > 0);
    
    int ret = SSL_write(ssl_, bin->data, static_cast<int>(bin->size));
    assert(ret > 0);
    return SendPending(env);
}

ERL_NIF_TERM TlsSocket::Handshake(ErlNifEnv *env)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);
    
    if(SSL_is_init_finished(ssl_))
        return make_ok_result(env, enif_make_int(env,1));
    
    int result = SSL_do_handshake(ssl_);

    if(result < 0)
        return make_error(env, enif_make_int(env, SSL_get_error(ssl_, result)));
    
    return make_ok_result(env, enif_make_int(env, result));
}

ERL_NIF_TERM TlsSocket::DoReadOp(ErlNifEnv *env)
{
    assert(ssl_);
    
    ByteBuffer buff(kTlsFrameSize);
    uint8_t buffer[kTlsFrameSize];
    int r;
    
    while((r = SSL_read(ssl_, buffer, kTlsFrameSize)) > 0)
        buff.WriteBytes(buffer, r);

    if(r < 0)
    {
        int error = SSL_get_error(ssl_, r);
        
        if(error != SSL_ERROR_WANT_READ)
        {
            std::string error_str = "DoReadOp failed with error: " + std::to_string(error);
            return make_error(env, error_str.c_str());
        }
    }
    
    SendPendingAsync(env);
    
    return make_binary(env, buff.Data(), buff.Length());
}

ERL_NIF_TERM TlsSocket::SendPending(ErlNifEnv *env)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);
        
    ERL_NIF_TERM term;
    int pending = BIO_pending(bio_write_);
    
    if (!pending)
    {
        enif_make_new_binary(env, 0, &term);
        return term;
    }
    
    unsigned char *destination_buffer = enif_make_new_binary(env, pending, &term);
    int read_bytes = BIO_read(bio_write_, destination_buffer, pending);
    
    assert(read_bytes == pending);
    
    return term;
}

ERL_NIF_TERM TlsSocket::SendPendingAsync(ErlNifEnv *env)
{
    assert(ssl_);
    
    int pending = BIO_pending(bio_write_);
    
    if (!pending)
        return ATOMS.atomOk;
    
    ERL_NIF_TERM term;
    
    std::unique_ptr<ErlNifEnv, decltype(&enif_free_env)> local_env(enif_alloc_env(), &enif_free_env);
    unsigned char *destination_buffer = enif_make_new_binary(local_env.get(), pending, &term);
    int read_bytes = BIO_read(bio_write_, destination_buffer, pending);
    assert(read_bytes == pending);
    
    ErlNifPid pid;
    
    if(enif_self(env, &pid) == NULL)
        return make_error(env, "failed to get the self pid");
    
    if(!enif_send(env, &pid, local_env.get(), enif_make_tuple(local_env.get(), 2 , ATOMS.atomSslWrite, term)))
        return make_error(env, "enif_send failed");
    
    return ATOMS.atomOk;
}


