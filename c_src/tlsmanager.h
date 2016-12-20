#ifndef ERLTLS_C_SRC_TLSMANAGER_H_
#define ERLTLS_C_SRC_TLSMANAGER_H_

#include <openssl/ssl.h>
#include "macros.h"

class TlsManager
{

public:
    
    static void InitOpenSSL();
    static void CleanupOpenSSL();
    static SSL_CTX* CreateContext(const char* cert_file, const char* ciphers, const char* dh_file, const char* ca_file);
    static int VerifyCallback(int preverify_ok, X509_STORE_CTX* ctx);
    
private:

    DISALLOW_IMPLICIT_CONSTRUCTORS(TlsManager);
};

#endif
