#include "tlssocket.h"
#include "tlsmanager.h"
#include "nif_utils.h"
#include "erltls_nif.h"
#include "bytebuffer.h"

#include <memory>

// http://roxlu.com/2014/042/using-openssl-with-memory-bios

static const int kTlsFrameSize = 16*1024;

void TlsSocket::SSlUserDataFree(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    UNUSED(parent);
    UNUSED(ad);
    UNUSED(idx);
    UNUSED(argl);
    UNUSED(argp);
    enif_free(ptr);
}

TlsSocket::TlsSocket() :
    bio_read_(NULL),
    bio_write_(NULL),
    ssl_(NULL)
{ }

TlsSocket::~TlsSocket()
{
    if (ssl_)
        SSL_free(ssl_);
}

bool TlsSocket::Init(SSL_CTX* ctx, kSslRole role, uint32_t flags, const std::string& session_cache)
{
    ssl_ = SSL_new(ctx);

    bio_read_ = BIO_new(BIO_s_mem());
    bio_write_ = BIO_new(BIO_s_mem());

    if(!bio_write_ || !bio_read_)
        return false;

    SSL_set_bio(ssl_, bio_read_, bio_write_);

    uint32_t options = SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION;

    if((flags & kFlagUseSessionTicket) == 0)
        options |= SSL_OP_NO_TICKET;

    if(role == kSslRoleServer)
        options |= SSL_OP_ALL;

    SSL_set_options(ssl_, options);

    if(!session_cache.empty())
    {
        SSL_SESSION *ssl_session = NULL;
        const uint8_t* i2d_data = reinterpret_cast<const uint8_t *>(session_cache.data());

        if(d2i_SSL_SESSION(&ssl_session, &i2d_data, session_cache.size()))
        {
            SSL_set_session(ssl_, ssl_session);
            SSL_SESSION_free(ssl_session);
        }
    }

    scoped_ptr(ssl_data, ssl_user_data, reinterpret_cast<ssl_user_data*>(enif_alloc(sizeof(ssl_user_data))), enif_free);
    ssl_data->peer_verify_result = ATOMS.atomOk;

    if(!SSL_set_ex_data(ssl_, TlsManager::GetSslUserDataIndex(), ssl_data.get()))
        return false;

    ssl_data.release();

    if(role == kSslRoleServer)
        SSL_set_accept_state(ssl_);
    else
        SSL_set_connect_state(ssl_);

    return true;
}

ERL_NIF_TERM TlsSocket::Shutdown(ErlNifEnv* env, const ErlNifBinary* bin)
{
    // Avoid calling SSL_shutdown() if handshake wasn't completed.
    if(!ssl_ || SSL_in_init(ssl_))
        return make_ok_result(env, enif_make_int(env, 1));

    if(bin->size)
        FeedData(env, bin);

    int ret = SSL_shutdown(ssl_);

    if(ret < 0)
    {
        int error = SSL_get_error(ssl_, ret);
        return make_error(env, enif_make_int(env, error));
    }

    int pending = BIO_pending(bio_write_);

    if (!pending)
        return make_ok_result(env, enif_make_int(env, ret));

    return enif_make_tuple3(env, ATOMS.atomOk, enif_make_int(env, ret), GetPendingData(env, pending));
}

ERL_NIF_TERM TlsSocket::FeedData(ErlNifEnv* env, const ErlNifBinary* bin)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);

    int ret = BIO_write(bio_read_, bin->data, static_cast<int>(bin->size));

    if(ret != static_cast<int>(bin->size))
        return make_error(env, "BIO_write failed");

    if (!SSL_is_init_finished(ssl_))
        return ATOMS.atomOk;

    ByteBuffer buff(kTlsFrameSize);
    uint8_t buffer[kTlsFrameSize];
    int r;

    while((r = SSL_read(ssl_, buffer, kTlsFrameSize)) > 0)
        buff.WriteBytes(buffer, r);

    consume_timeslice(env, bin->size);

    if(r < 0 || buff.Length() == 0)
    {
        int error = SSL_get_error(ssl_, r);

        if(error != SSL_ERROR_WANT_READ)
            return make_error(env, enif_make_int(env, error));
    }

    return make_ok_result(env, make_binary(env, buff.Data(), buff.Length()));
}

ERL_NIF_TERM TlsSocket::SendData(ErlNifEnv* env, const ErlNifBinary* bin)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);

    ASSERT(bin->size > 0);

    int ret = SSL_write(ssl_, bin->data, static_cast<int>(bin->size));

    consume_timeslice(env, bin->size);

    if(ret <= 0)
    {
        int error = SSL_get_error(ssl_, ret);
        return make_error(env, enif_make_int(env, error));
    }

    return SendPending(env);
}

ERL_NIF_TERM TlsSocket::Handshake(ErlNifEnv* env)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);

    if(SSL_is_init_finished(ssl_))
        return make_ok_result(env, enif_make_int(env, 1));

    int result = SSL_do_handshake(ssl_);

    if(result != 1)
    {
        int error = SSL_get_error(ssl_, result);

        if(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
            return make_error(env, enif_make_int(env, error));

        ssl_user_data* data = reinterpret_cast<ssl_user_data*>(SSL_get_ex_data(ssl_, TlsManager::GetSslUserDataIndex()));
        if(!enif_is_identical(data->peer_verify_result, ATOMS.atomOk))
            return make_error(env, data->peer_verify_result);
        else
            return make_error(env, enif_make_int(env, error));
    }

    return ATOMS.atomOk;
}

ERL_NIF_TERM TlsSocket::SendPending(ErlNifEnv* env)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);

    ERL_NIF_TERM term;
    int pending = BIO_pending(bio_write_);

    if (!pending)
    {
        enif_make_new_binary(env, 0, &term);
        return make_ok_result(env, term);
    }

    return make_ok_result(env, GetPendingData(env, pending));
}

ERL_NIF_TERM TlsSocket::GetPendingData(ErlNifEnv *env, int pending)
{
    ERL_NIF_TERM term;
    unsigned char *destination_buffer = enif_make_new_binary(env, pending, &term);
    int read_bytes = BIO_read(bio_write_, destination_buffer, pending);
    ASSERT(read_bytes == pending);
    return term;
}

ERL_NIF_TERM TlsSocket::IsSessionReused(ErlNifEnv* env)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);

    return SSL_session_reused(ssl_) ? ATOMS.atomTrue : ATOMS.atomFalse;
}

ERL_NIF_TERM TlsSocket::GetSessionASN1(ErlNifEnv *env)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);

    SSL_SESSION* ssl_session = SSL_get_session(ssl_);

    if(!ssl_session)
        return make_error(env, "session not available");

    // session asn1
    int session_asn1_size = i2d_SSL_SESSION(ssl_session, NULL);

    if(session_asn1_size <= 0)
        return make_error(env, "failed to get session size");

    std::unique_ptr<uint8_t[]> session_asn1(new uint8_t[session_asn1_size]);
    uint8_t* ptr = session_asn1.get();

    if (i2d_SSL_SESSION(ssl_session, &ptr) < 1)
        return make_error(env, "failed to serialize session");
#ifdef OPENSSL_IS_BORINGSSL
    ERL_NIF_TERM has_ticket = SSL_SESSION_has_ticket(ssl_session) ? ATOMS.atomTrue : ATOMS.atomFalse;
#else
    ERL_NIF_TERM has_ticket = ssl_session->tlsext_ticklen > 0 ? ATOMS.atomTrue : ATOMS.atomFalse;
#endif
    return enif_make_tuple3(env, ATOMS.atomOk, has_ticket, make_binary(env, session_asn1.get(), session_asn1_size));
}

ERL_NIF_TERM TlsSocket::GetPeerCert(ErlNifEnv *env)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);

    scoped_ptr(cert, X509, SSL_get_peer_certificate(ssl_), X509_free);

    if(cert.get() == NULL)
        return make_error(env, ATOMS.atomError_enopeercert);

    int len = i2d_X509(cert.get(), NULL);

    if (len <= 0)
        return make_error(env, ATOMS.atomError_epeercert);

    std::unique_ptr<uint8_t[]> cert_str(new uint8_t[len]);
    uint8_t* tmp = cert_str.get();

    // We must use a temporary value here, since i2d_X509(X509 *x, unsigned char **out) increments *out.

    if (i2d_X509(cert.get(), &tmp) < 0)
        return make_error(env, ATOMS.atomError_epeercert);

    return make_ok_result(env, make_binary(env, cert_str.get(), len));
}

ERL_NIF_TERM TlsSocket::GetSslMethod(ErlNifEnv* env)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);

    std::string version = SSL_get_version(ssl_);
    ERL_NIF_TERM term;

    if(ProtocolToAtom(version, &term))
        return make_ok_result(env, term);

    return make_error(env, version.c_str());
}

ERL_NIF_TERM TlsSocket::GetSessionInfo(ErlNifEnv* env)
{
    if(!ssl_)
        return make_error(env, ATOMS.atomSslNotStarted);

    std::string version = SSL_get_version(ssl_);
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_);

    if(cipher == NULL)
        return make_error(env, ATOMS.atomSslNotStarted);

    ERL_NIF_TERM protocol_term;

    if(!ProtocolToAtom(version, &protocol_term))
        return make_error(env, ATOMS.atomSslNotStarted);

    std::string cipher_name = SSL_CIPHER_get_name(cipher);
    ERL_NIF_TERM cipher_term = make_binary(env, reinterpret_cast<const uint8_t*>(cipher_name.c_str()), cipher_name.length());

    ERL_NIF_TERM protocol_item = enif_make_tuple(env, 2, ATOMS.atomCtxTlsProtocol, protocol_term);
    ERL_NIF_TERM cipher_item = enif_make_tuple(env, 2, ATOMS.atomSslCipherSuite, cipher_term);

    return make_ok_result(env, enif_make_list(env, 2, protocol_item, cipher_item));
}

bool TlsSocket::ProtocolToAtom(const std::string& protocol, ERL_NIF_TERM* term)
{
    // from ssl/ssl_lib.c

    if(protocol == "TLSv1.3")
    {
        *term = ATOMS.atomSSLMethodTLSv1_3;
        return true;
    }
    else if(protocol == "TLSv1.2")
    {
        *term = ATOMS.atomSSLMethodTLSv1_2;
        return true;
    }
    else if(protocol == "TLSv1.1")
    {
        *term = ATOMS.atomSSLMethodTLSv1_1;
        return true;
    }
    else if(protocol == "TLSv1")
    {
        *term = ATOMS.atomSSLMethodTLSv1;
        return true;
    }
    else if(protocol == "SSLv3")
    {
#ifndef OPENSSL_IS_BORINGSSL
        *term = ATOMS.atomSSLMethodSSLv3;
        return true;
#else
        return false;
#endif
    }
    else if(protocol == "DTLSv1.2")
    {
        *term = ATOMS.atomSSLMethodDTLSv1_2;
        return true;
    }
    else if(protocol == "DTLSv1")
    {
        *term = ATOMS.atomSSLMethodDTLSv1;
        return true;
    }

    return false;
}
