#include "tlsmanager.h"
#include "ssldh.h"
#include "erl_nif.h"

#include <openssl/err.h>
#include <memory>

//@todo:
//1. implement verify callback

void TlsManager::InitOpenSSL()
{
#ifndef OPENSSL_IS_BORINGSSL
    CRYPTO_set_mem_functions(enif_alloc, enif_realloc, enif_free);
#endif
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

void TlsManager::CleanupOpenSSL()
{
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_cleanup();
#endif
}

int TlsManager::VerifyCallback(int preverify_ok, X509_STORE_CTX* ctx)
{
    UNUSED(preverify_ok);
    UNUSED(ctx);
    return 1;
}

SSL_CTX* TlsManager::CreateContext(const ContextProperties& props)
{
    scoped_ptr(ctx, SSL_CTX, SSL_CTX_new(SSLv23_method()), SSL_CTX_free);
    
    if(!ctx.get())
        return NULL;
    
    if(!props.cert_file.empty())
    {
        if(!SSL_CTX_use_certificate_chain_file(ctx.get(), props.cert_file.c_str()))
            return NULL;
    
        if(!SSL_CTX_use_PrivateKey_file(ctx.get(), props.cert_file.c_str(), SSL_FILETYPE_PEM))
            return NULL;
    
        if(!SSL_CTX_check_private_key(ctx.get()))
            return NULL;
    }

    assert(props.ciphers.empty() == false);
    
    if(!SSL_CTX_set_cipher_list(ctx.get(), props.ciphers.c_str()))
        return NULL;
    
#ifndef OPENSSL_NO_ECDH
    SetupECDH(ctx.get());
#endif
    
#ifndef OPENSSL_NO_DH
    if(!SetupDH(ctx.get(), props.dh_file))
        return NULL;
#endif
    
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
    
    if (!props.ca_file.empty())
        SSL_CTX_load_verify_locations(ctx.get(), props.ca_file.c_str(), NULL);
    else
        SSL_CTX_set_default_verify_paths(ctx.get());
    
#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ctx.get(), SSL_MODE_RELEASE_BUFFERS);
#endif
    
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, VerifyCallback);
    
    return ctx.release();
}
