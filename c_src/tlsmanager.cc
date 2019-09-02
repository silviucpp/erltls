#include "tlsmanager.h"
#include "ssldh.h"
#include "erl_nif.h"
#include "erltls_nif.h"
#include "nif_utils.h"
#include "tlssocket.h"

#include <openssl/rand.h>
#include <openssl/err.h>
#include <memory>
#include <string.h>
#include <algorithm>

struct callback_data
{
    int verify_depth;
    char* password;
    int password_length;
};

static char kCallbackDataTag[] = "callback_data";
static char kSslUserDataTag[] = "ssl_user_data";

static int callback_data_index = -1;
static int ssl_user_data_index = -1;

void callback_data_free(void *ptr)
{
    callback_data *cb_data = reinterpret_cast<callback_data*>(ptr);

    if(cb_data->password)
        enif_free(cb_data->password);

    enif_free(ptr);
}

static void ssl_callback_data_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    UNUSED(parent);
    UNUSED(ad);
    UNUSED(idx);
    UNUSED(argl);
    UNUSED(argp);
    callback_data_free(ptr);
}

void TlsManager::InitOpenSSL()
{
#ifndef OPENSSL_IS_BORINGSSL
    CRYPTO_set_mem_functions(enif_alloc, enif_realloc, enif_free);
#endif
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    callback_data_index = SSL_CTX_get_ex_new_index(0, reinterpret_cast<void*>(kCallbackDataTag), NULL, NULL, ssl_callback_data_free);
    ssl_user_data_index = SSL_CTX_get_ex_new_index(0, reinterpret_cast<void*>(kSslUserDataTag), NULL, NULL, TlsSocket::SSlUserDataFree);
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

int TlsManager::GetSslUserDataIndex()
{
    return ssl_user_data_index;
}

int TlsManager::VerifyCallback(int ok, X509_STORE_CTX *x509_ctx)
{
    int cert_err = X509_STORE_CTX_get_error(x509_ctx);
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    SSL *ssl = reinterpret_cast<SSL*>(X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);

    callback_data* cb_data = reinterpret_cast<callback_data*>(SSL_CTX_get_ex_data(ctx, callback_data_index));
    ssl_user_data* ssl_data = reinterpret_cast<ssl_user_data*>(SSL_get_ex_data(ssl, ssl_user_data_index));

    if (!ok && depth >= cb_data->verify_depth)
        ok = 1;

    switch (cert_err)
    {
        case X509_V_OK:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            ok = 1;
            break;

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            ssl_data->peer_verify_result = ATOMS.atomError_enoissuercert;
            break;

        case X509_V_ERR_CERT_HAS_EXPIRED:
            ssl_data->peer_verify_result = ATOMS.atomError_epeercertexpired;
            break;

        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            ssl_data->peer_verify_result = ATOMS.atomError_epeercertinvalid;
            break;

        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            ssl_data->peer_verify_result = ATOMS.atomError_eselfsignedcert;
            break;

        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            ssl_data->peer_verify_result = ATOMS.atomError_echaintoolong;
            break;

        default:
            ssl_data->peer_verify_result = ATOMS.atomError_epeercert;
            break;
    }

    return ok;
}

int TlsManager::PasswdCallback(char *buf, int num, int rwflag, void *userdata)
{
    UNUSED(rwflag);

    callback_data *cb_data = reinterpret_cast<callback_data*>(userdata);

    if (cb_data && cb_data->password)
    {
        strncpy(buf, cb_data->password, num);
        return cb_data->password_length;
    }

    return 0;
}

SSL_CTX* TlsManager::CreateContext(const ContextProperties& props)
{
    scoped_ptr(ctx, SSL_CTX, SSL_CTX_new(props.tls_proto), SSL_CTX_free);
    scoped_ptr(cb_data, callback_data, reinterpret_cast<callback_data*>(enif_alloc(sizeof(callback_data))), callback_data_free);

    if(!ctx.get() || !cb_data.get())
        return NULL;

    cb_data->verify_depth = props.verify_depth;
    cb_data->password = NULL;
    cb_data->password_length = 0;

    if(!SSL_CTX_set_ex_data(ctx.get(), callback_data_index, cb_data.get()))
        return NULL;

    if(!props.password.empty())
    {
        cb_data->password = reinterpret_cast<char*>(enif_alloc(props.password.size() + 1));
        cb_data->password_length = static_cast<int>(props.password.size());
        std::copy(props.password.begin(), props.password.end(), cb_data->password);
        cb_data->password[props.password.size()] = '\0';

        SSL_CTX_set_default_passwd_cb(ctx.get(), PasswdCallback);
        SSL_CTX_set_default_passwd_cb_userdata(ctx.get(), cb_data.get());
    }

    cb_data.release();

    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);

    if(props.reuse_sessions_ttl_sec)
        SSL_CTX_set_timeout(ctx.get(), props.reuse_sessions_ttl_sec);

    if(!props.certfile.empty())
    {
        if(!SSL_CTX_use_certificate_chain_file(ctx.get(), props.certfile.c_str()))
            return NULL;

        std::string privatekey = props.keyfile.empty() ? props.certfile : props.keyfile;

        if(!SSL_CTX_use_PrivateKey_file(ctx.get(), privatekey.c_str(), SSL_FILETYPE_PEM))
            return NULL;

        if(!SSL_CTX_check_private_key(ctx.get()))
            return NULL;

        // sessing ticketing make sense only in case private key was set

        if(props.use_session_ticket)
        {
            std::string ticket_secret_key = props.session_ticket_skey;

            // generate random key in case none was provided
            if(ticket_secret_key.empty())
            {
                uint8_t key[32];
                if(RAND_bytes(key, sizeof(key)) <= 0)
                    return NULL;

                ticket_secret_key = std::string(reinterpret_cast<const char*>(key), sizeof(key));
            }

            uint8_t keys[48] = {0};

            EVP_PKEY *pkey = SSL_CTX_get0_privatekey(ctx.get());

            if(pkey == NULL)
                return NULL;

            uint siglen;
            uint8_t sign[256] = {0};
            EVP_MD_CTX mdctx;
            EVP_MD_CTX_init(&mdctx);
            EVP_SignInit(&mdctx, EVP_sha256());
            EVP_SignUpdate(&mdctx, ticket_secret_key.data(), ticket_secret_key.length());
            EVP_SignFinal(&mdctx, sign, &siglen, pkey);
            EVP_MD_CTX_cleanup(&mdctx);
            memcpy(keys, sign, sizeof(keys));

            if(!SSL_CTX_set_tlsext_ticket_keys(ctx.get(), keys, sizeof(keys)))
                return NULL;
        }
    }

    ASSERT(props.ciphers.empty() == false);

    if(!SSL_CTX_set_cipher_list(ctx.get(), props.ciphers.c_str()))
        return NULL;

#ifndef OPENSSL_NO_ECDH
    SetupECDH(ctx.get());
#endif

#ifndef OPENSSL_NO_DH
    if(!SetupDH(ctx.get(), props.dh_file))
        return NULL;
#endif

    if (!props.ca_certfile.empty())
        SSL_CTX_load_verify_locations(ctx.get(), props.ca_certfile.c_str(), NULL);
    else
        SSL_CTX_set_default_verify_paths(ctx.get());

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ctx.get(), SSL_MODE_RELEASE_BUFFERS);
#endif

    SSL_CTX_set_verify_depth(ctx.get(), props.verify_depth);
    SSL_CTX_set_verify(ctx.get(), GetSSLVerifyFlags(props.verify_mode, props.fail_if_no_peer_cert), VerifyCallback);

    return ctx.release();
}

int TlsManager::GetSSLVerifyFlags(int verify, bool fail_if_no_peer_cert)
{
    int flags =  fail_if_no_peer_cert ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0;

    switch (verify)
    {
        case VERIFY_NONE:
            flags |= SSL_VERIFY_NONE;
            break;

        case VERIFY_PEER:
            flags |= SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE;
            break;

        default:
            flags = SSL_VERIFY_NONE;
    }

    return flags;
}

ERL_NIF_TERM TlsManager::GetOpenSSLVersion(ErlNifEnv* env)
{
    std::string ssl_compile_version = OPENSSL_VERSION_TEXT;
    std::string ssl_lib_version = SSLeay_version(SSLEAY_VERSION);

    ERL_NIF_TERM comp_version_item = enif_make_tuple(env, 2, ATOMS.atomCompileVersion, make_binary(env, ssl_compile_version));
    ERL_NIF_TERM lib_version_item = enif_make_tuple(env, 2, ATOMS.atomLibVersion, make_binary(env, ssl_lib_version));

    return make_ok_result(env, enif_make_list(env, 2, comp_version_item, lib_version_item));
}
