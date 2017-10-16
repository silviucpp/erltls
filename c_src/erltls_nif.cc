#include "erltls_nif.h"
#include "nif_utils.h"
#include "macros.h"
#include "nif_ssl_context.h"
#include "nif_ssl_socket.h"
#include "tlsmanager.h"

const char kAtomOk[] = "ok";
const char kAtomTrue[] = "true";
const char kAtomFalse[] = "false";
const char kAtomError[] = "error";
const char kAtomBadArg[] = "badarg";
const char kAtomOptions[] = "options";

const char kAtomSSLMethodSSLv3[] = "sslv3";
const char kAtomSSLMethodTLSv1[] = "tlsv1";
const char kAtomSSLMethodTLSv1_1[] = "tlsv1.1";
const char kAtomSSLMethodTLSv1_2[] = "tlsv1.2";
const char kAtomSSLMethodTLSv1_3[] = "tlsv1.3";
const char kAtomSSLMethodDTLSv1[] = "dtlsv1";
const char kAtomSSLMethodDTLSv1_2[] = "dtlsv1.2";

const char kAtomError_enoissuercert[] = "enoissuercert";
const char kAtomError_epeercertexpired[] = "epeercertexpired";
const char kAtomError_epeercertinvalid[] = "epeercertinvalid";
const char kAtomError_eselfsignedcert[] = "eselfsignedcert";
const char kAtomError_echaintoolong[] = "echaintoolong";
const char kAtomError_epeercert[] = "epeercert";
const char kAtomError_enopeercert[] = "enopeercert";

const char kAtomVerifyNone[] = "verify_none";
const char kAtomVerifyPeer[] = "verify_peer";

const char kAtomSllNotStarted[] = "ssl_not_started";
const char kAtomSslCipherSuite[] = "cipher_suite";

const char kAtomCtxTlsProtocol[] = "protocol";
const char kAtomCtxCertfile[] = "certfile";
const char kAtomCtxDhfile[] = "dhfile";
const char kAtomCtxCaCertFile[] = "cacertfile";
const char kAtomCtxKeyfile[] = "keyfile";
const char kAtomCtxPassword[] = "password";
const char kAtomCtxCiphers[] = "ciphers";
const char kAtomCtxReuseSessionsTtl[] = "reuse_sessions_ttl";
const char kAtomCtxUseSessionTicket[] = "use_session_ticket";
const char kAtomCtxVerify[] = "verify";
const char kAtomCtxFailIfNoPeerCert[] = "fail_if_no_peer_cert";
const char kAtomCtxDepth[] = "depth";

const char kAtomCompileVersion[] = "compile_version";
const char kAtomLibVersion[] = "lib_version";

atoms ATOMS;

void open_resources(ErlNifEnv* env, erltls_data* data)
{
    ErlNifResourceFlags flags =  static_cast<ErlNifResourceFlags>(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);
    data->res_ssl_ctx = enif_open_resource_type(env, NULL, "enif_ssl_ctx", enif_ssl_ctx_free, flags, NULL);
    data->res_ssl_sock = enif_open_resource_type(env, NULL, "enif_ssl_sock", enif_ssl_socket_free, flags, NULL);
}

int on_nif_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    UNUSED(load_info);

    TlsManager::InitOpenSSL();

    ATOMS.atomOk = make_atom(env, kAtomOk);
    ATOMS.atomTrue = make_atom(env, kAtomTrue);
    ATOMS.atomFalse = make_atom(env, kAtomFalse);
    ATOMS.atomError = make_atom(env, kAtomError);
    ATOMS.atomOptions = make_atom(env, kAtomOptions);
    ATOMS.atomBadArg = make_atom(env, kAtomBadArg);

    ATOMS.atomSSLMethodSSLv3 = make_atom(env, kAtomSSLMethodSSLv3);
    ATOMS.atomSSLMethodTLSv1 = make_atom(env, kAtomSSLMethodTLSv1);
    ATOMS.atomSSLMethodTLSv1_1 = make_atom(env, kAtomSSLMethodTLSv1_1);
    ATOMS.atomSSLMethodTLSv1_2 = make_atom(env, kAtomSSLMethodTLSv1_2);
    ATOMS.atomSSLMethodTLSv1_3 = make_atom(env, kAtomSSLMethodTLSv1_3);
    ATOMS.atomSSLMethodDTLSv1 = make_atom(env, kAtomSSLMethodDTLSv1);
    ATOMS.atomSSLMethodDTLSv1_2 = make_atom(env, kAtomSSLMethodDTLSv1_2);

    ATOMS.atomError_enoissuercert = make_atom(env, kAtomError_enoissuercert);
    ATOMS.atomError_epeercertexpired = make_atom(env, kAtomError_epeercertexpired);
    ATOMS.atomError_epeercertinvalid = make_atom(env, kAtomError_epeercertinvalid);
    ATOMS.atomError_eselfsignedcert = make_atom(env, kAtomError_eselfsignedcert);
    ATOMS.atomError_echaintoolong = make_atom(env, kAtomError_echaintoolong);
    ATOMS.atomError_epeercert = make_atom(env, kAtomError_epeercert);
    ATOMS.atomError_enopeercert = make_atom(env, kAtomError_enopeercert);

    ATOMS.atomVerifyNone = make_atom(env, kAtomVerifyNone);
    ATOMS.atomVerifyPeer = make_atom(env, kAtomVerifyPeer);

    ATOMS.atomSslNotStarted = make_atom(env, kAtomSllNotStarted);
    ATOMS.atomSslCipherSuite = make_atom(env, kAtomSslCipherSuite);

    ATOMS.atomCtxTlsProtocol = make_atom(env, kAtomCtxTlsProtocol);
    ATOMS.atomCtxCertfile = make_atom(env, kAtomCtxCertfile);
    ATOMS.atomCtxKeyfile = make_atom(env, kAtomCtxKeyfile);
    ATOMS.atomCtxPassword = make_atom(env, kAtomCtxPassword);
    ATOMS.atomCtxDhfile = make_atom(env, kAtomCtxDhfile);
    ATOMS.atomCtxCaCertFile = make_atom(env, kAtomCtxCaCertFile);
    ATOMS.atomCtxCiphers = make_atom(env, kAtomCtxCiphers);
    ATOMS.atomCtxReuseSessionsTtl = make_atom(env, kAtomCtxReuseSessionsTtl);
    ATOMS.atomCtxUseSessionTicket = make_atom(env, kAtomCtxUseSessionTicket);

    ATOMS.atomCtxVerify = make_atom(env, kAtomCtxVerify);
    ATOMS.atomCtxFailIfNoPeerCert = make_atom(env, kAtomCtxFailIfNoPeerCert);
    ATOMS.atomCtxDepth = make_atom(env, kAtomCtxDepth);

    ATOMS.atomCompileVersion = make_atom(env, kAtomCompileVersion);
    ATOMS.atomLibVersion = make_atom(env, kAtomLibVersion);

    erltls_data* data = static_cast<erltls_data*>(enif_alloc(sizeof(erltls_data)));
    open_resources(env, data);

    *priv_data = data;
    return 0;
}

void on_nif_unload(ErlNifEnv* env, void* priv_data)
{
    UNUSED(env);
    erltls_data* data = static_cast<erltls_data*>(priv_data);
    enif_free(data);
    TlsManager::CleanupOpenSSL();
}

int on_nif_upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM info)
{
    UNUSED(old_priv);
    UNUSED(info);

    erltls_data* data = static_cast<erltls_data*>(enif_alloc(sizeof(erltls_data)));
    open_resources(env, data);

    *priv = data;
    return 0;
}

static ErlNifFunc nif_funcs[] =
{
    {"new_context", 1, enif_ssl_new_context},
    {"ciphers", 1, enif_ciphers},
    {"ssl_new", 4, enif_ssl_socket_new},
    {"ssl_set_owner", 2, enif_ssl_socket_set_owner},
    {"ssl_handshake", 1, enif_ssl_socket_handshake},
    {"ssl_send_pending", 1, enif_ssl_socket_send_pending},
    {"ssl_feed_data", 2, enif_ssl_socket_feed_data},
    {"ssl_send_data", 2, enif_ssl_socket_send_data},
    {"ssl_get_session_asn1", 1, enif_ssl_socket_get_session_ans1},
    {"ssl_session_reused", 1, enif_ssl_socket_session_reused},
    {"ssl_peercert", 1, enif_ssl_socket_peercert},
    {"ssl_get_method", 1, enif_ssl_socket_get_method},
    {"ssl_get_session_info", 1, enif_ssl_socket_get_session_info},
    {"ssl_shutdown", 2, enif_ssl_socket_shutdown},
    {"version", 0, enif_openssl_version},
};

ERL_NIF_INIT(erltls_nif, nif_funcs, on_nif_load, NULL, on_nif_upgrade, on_nif_unload)
