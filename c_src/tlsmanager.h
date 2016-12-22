#ifndef ERLTLS_C_SRC_TLSMANAGER_H_
#define ERLTLS_C_SRC_TLSMANAGER_H_

#include <openssl/ssl.h>
#include <string>
#include "macros.h"

struct ContextProperties
{
    std::string cert_file;
    std::string ciphers;
    std::string dh_file;
    std::string ca_file;
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
