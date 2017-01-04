#ifndef ERLTLS_C_SRC_TLSSOCKET_H_
#define ERLTLS_C_SRC_TLSSOCKET_H_

#include <openssl/ssl.h>
#include <string>

#include "macros.h"
#include "erl_nif.h"

class TlsSocket
{
public:

    static const int kFlagCompressionNone = 1;
    static const int kFlagUseSessionTicket = 2;

    enum kSslRole {kSslRoleServer = 1, kSslRoleClient};
    
    TlsSocket();
    ~TlsSocket();
    
    bool Init(SSL_CTX* context, kSslRole role, long flags, const std::string& session_cache);
    
    ERL_NIF_TERM Handshake(ErlNifEnv *env);
    ERL_NIF_TERM SendPending(ErlNifEnv *env);
    
    ERL_NIF_TERM FeedData(ErlNifEnv *env, const ErlNifBinary* bin);
    ERL_NIF_TERM SendData(ErlNifEnv *env, const ErlNifBinary* bin);

    ERL_NIF_TERM IsSessionReused(ErlNifEnv *env);
    ERL_NIF_TERM GetSessionASN1(ErlNifEnv *env);

    ERL_NIF_TERM Shutdown(ErlNifEnv *env);

private:

    DISALLOW_COPY_AND_ASSIGN(TlsSocket);
    
    ERL_NIF_TERM SendPendingAsync(ErlNifEnv *env);
    ERL_NIF_TERM DoHandshakeOp(ErlNifEnv *env);
    ERL_NIF_TERM DoReadOp(ErlNifEnv *env);
    
    BIO* bio_read_;
    BIO* bio_write_;
    SSL* ssl_;
};

#endif
