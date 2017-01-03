#ifndef ERLTLS_C_SRC_TLSMANAGER_H_
#define ERLTLS_C_SRC_TLSMANAGER_H_

#include <openssl/ssl.h>
#include <string>
#include "macros.h"

struct ContextProperties
{
    ContextProperties() : reuse_sessions_ttl_sec(300), use_session_ticket(false) {}

    std::string cert_file;
    std::string ciphers;
    std::string dh_file;
    std::string ca_file;

    uint32_t reuse_sessions_ttl_sec;
    bool use_session_ticket;
    std::string session_ticket_skey;
};

class TlsManager
{

public:

    static void InitOpenSSL();
    static void CleanupOpenSSL();
    static SSL_CTX* CreateContext(const ContextProperties& props);
    static int VerifyCallback(int preverify_ok, X509_STORE_CTX* ctx);

private:

    DISALLOW_IMPLICIT_CONSTRUCTORS(TlsManager);
};

#endif
