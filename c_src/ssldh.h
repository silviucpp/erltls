#ifndef ERLTLS_C_SRC_SSLDH_H_
#define ERLTLS_C_SRC_SSLDH_H_

#include <openssl/ssl.h>
#include <string>

#ifndef OPENSSL_NO_DH
int SetupDH(SSL_CTX* ctx, const std::string& dh_file);
#endif

#ifndef OPENSSL_NO_ECDH
void SetupECDH(SSL_CTX* ctx);
#endif

#endif
