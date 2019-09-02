#ifndef C_SRC_TLSMANAGER_H_
#define C_SRC_TLSMANAGER_H_

#include <openssl/ssl.h>
#include <string>
#include "macros.h"
#include "erl_nif.h"

#define DEFAULT_VERIFY_DEPTH 1
#define VERIFY_NONE 0
#define VERIFY_PEER 1

struct ContextProperties
{
    ContextProperties() :
        tls_proto(SSLv23_method()),
        reuse_sessions_ttl_sec(300),
        use_session_ticket(false),
        fail_if_no_peer_cert(false),
        verify_depth(DEFAULT_VERIFY_DEPTH),
        verify_mode(VERIFY_NONE)
    {}

    const SSL_METHOD* tls_proto;
    std::string certfile;
    std::string keyfile;
    std::string password;
    std::string ciphers;
    std::string dh_file;
    std::string ca_certfile;

    uint32_t reuse_sessions_ttl_sec;
    bool use_session_ticket;
    std::string session_ticket_skey;

    bool fail_if_no_peer_cert;
    int verify_depth;
    int verify_mode;
};

class TlsManager
{

public:

    static void InitOpenSSL();
    static void CleanupOpenSSL();
    static int GetSslUserDataIndex();

    static ERL_NIF_TERM GetOpenSSLVersion(ErlNifEnv* env);

    static SSL_CTX* CreateContext(const ContextProperties& props);
    static int VerifyCallback(int preverify_ok, X509_STORE_CTX* ctx);
    static int PasswdCallback(char* buf, int num, int rwflag, void* userdata);
    static int GetSSLVerifyFlags(int verify, bool fail_if_no_peer_cert);

private:

    DISALLOW_IMPLICIT_CONSTRUCTORS(TlsManager);
};

#endif  // C_SRC_TLSMANAGER_H_
