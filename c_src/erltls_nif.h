#ifndef C_SRC_ERLTLS_NIF_H_
#define C_SRC_ERLTLS_NIF_H_

#include "erl_nif.h"

struct atoms
{
    ERL_NIF_TERM atomOk;
    ERL_NIF_TERM atomTrue;
    ERL_NIF_TERM atomFalse;
    ERL_NIF_TERM atomError;
    ERL_NIF_TERM atomBadArg;
    ERL_NIF_TERM atomOptions;

    ERL_NIF_TERM atomSSLMethodSSLv3;
    ERL_NIF_TERM atomSSLMethodTLSv1;
    ERL_NIF_TERM atomSSLMethodTLSv1_1;
    ERL_NIF_TERM atomSSLMethodTLSv1_2;
    ERL_NIF_TERM atomSSLMethodTLSv1_3;
    ERL_NIF_TERM atomSSLMethodDTLSv1;
    ERL_NIF_TERM atomSSLMethodDTLSv1_2;

    ERL_NIF_TERM atomError_enoissuercert;
    ERL_NIF_TERM atomError_epeercertexpired;
    ERL_NIF_TERM atomError_epeercertinvalid;
    ERL_NIF_TERM atomError_eselfsignedcert;
    ERL_NIF_TERM atomError_echaintoolong;
    ERL_NIF_TERM atomError_epeercert;
    ERL_NIF_TERM atomError_enopeercert;

    ERL_NIF_TERM atomVerifyNone;
    ERL_NIF_TERM atomVerifyPeer;

    ERL_NIF_TERM atomSslNotStarted;
    ERL_NIF_TERM atomSslCipherSuite;

    ERL_NIF_TERM atomCtxTlsProtocol;
    ERL_NIF_TERM atomCtxCertfile;
    ERL_NIF_TERM atomCtxKeyfile;
    ERL_NIF_TERM atomCtxPassword;
    ERL_NIF_TERM atomCtxDhfile;
    ERL_NIF_TERM atomCtxCaCertFile;
    ERL_NIF_TERM atomCtxCiphers;
    ERL_NIF_TERM atomCtxReuseSessionsTtl;
    ERL_NIF_TERM atomCtxUseSessionTicket;

    ERL_NIF_TERM atomCtxVerify;
    ERL_NIF_TERM atomCtxFailIfNoPeerCert;
    ERL_NIF_TERM atomCtxDepth;

    ERL_NIF_TERM atomCompileVersion;
    ERL_NIF_TERM atomLibVersion;
};

struct erltls_data
{
    ErlNifResourceType* res_ssl_ctx;
    ErlNifResourceType* res_ssl_sock;
};

extern atoms ATOMS;

#endif  // C_SRC_ERLTLS_NIF_H_
