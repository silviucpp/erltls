#ifndef ERLTLS_C_SRC_SSLDH_H_
#define ERLTLS_C_SRC_SSLDH_H_

#include <openssl/ssl.h>

#ifndef OPENSSL_NO_DH
int SetupDH(SSL_CTX* ctx, const char* dh_file);
#endif

#ifndef OPENSSL_NO_ECDH
void SetupECDH(SSL_CTX* ctx);
#endif

#endif
