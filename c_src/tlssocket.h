#ifndef C_SRC_TLSSOCKET_H_
#define C_SRC_TLSSOCKET_H_

#include <openssl/ssl.h>
#include <string>

#include "macros.h"
#include "erl_nif.h"

struct ssl_user_data
{
    ERL_NIF_TERM peer_verify_result;
};

class SocketOwner
{
public:

    SocketOwner() : is_set_(false), pid_{0} {}
    explicit SocketOwner(const ErlNifPid& p) : is_set_(true), pid_(p) {}

    bool is_set() const { return is_set_;}
    const ErlNifPid& pid() const { return pid_;}

private:
    bool is_set_;
    ErlNifPid pid_;
};

class TlsSocket
{
public:

    static const int kFlagUseSessionTicket = 1;

    enum kSslRole {kSslRoleServer = 1, kSslRoleClient};

    TlsSocket();
    ~TlsSocket();

    bool Init(SSL_CTX* context, kSslRole role, uint32_t flags, const std::string& session_cache);
    void SetOwnerProcess(const SocketOwner& owner) {owner_ = owner;}

    ERL_NIF_TERM Handshake(ErlNifEnv *env);
    ERL_NIF_TERM SendPending(ErlNifEnv *env);
    ERL_NIF_TERM FeedData(ErlNifEnv *env, const ErlNifBinary* bin);
    ERL_NIF_TERM SendData(ErlNifEnv *env, const ErlNifBinary* bin);
    ERL_NIF_TERM Shutdown(ErlNifEnv *env, const ErlNifBinary* bin);

    ERL_NIF_TERM IsSessionReused(ErlNifEnv *env);
    ERL_NIF_TERM GetSessionASN1(ErlNifEnv *env);
    ERL_NIF_TERM GetPeerCert(ErlNifEnv *env);
    ERL_NIF_TERM GetSslMethod(ErlNifEnv* env);
    ERL_NIF_TERM GetSessionInfo(ErlNifEnv* env);

    static void SSlUserDataFree(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);

private:

    ERL_NIF_TERM SendPendingAsync(ErlNifEnv *env);
    ERL_NIF_TERM DoHandshakeOp(ErlNifEnv *env);
    ERL_NIF_TERM GetPendingData(ErlNifEnv *env, int pending);
    bool ProtocolToAtom(const std::string& protocol, ERL_NIF_TERM* term);

    SocketOwner owner_;
    BIO* bio_read_;
    BIO* bio_write_;
    SSL* ssl_;

    DISALLOW_COPY_AND_ASSIGN(TlsSocket);
};

#endif  // C_SRC_TLSSOCKET_H_
