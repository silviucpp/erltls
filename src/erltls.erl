-module(erltls).
-author("silviu.caragea").

-include("erltls.hrl").

-export([
    cipher_suites/0,
    clear_pem_cache/0,
    connect/2,
    connect/3,
    connect/4,
    controlling_process/2,
    getopts/2,
    setopts/2,
    getstat/1,
    getstat/2,
    peername/1,
    listen/2,
    transport_accept/1,
    transport_accept/2,
    ssl_accept/1,
    send/2,
    recv/2,
    recv/3,
    close/1
]).

cipher_suites() ->
    case erltls_manager:get_ctx(null, null, null, null, false) of
        {ok, Ctx} ->
            erltls_nif:ciphers(Ctx);
        _ ->
            {error, <<"invalid ssl context">>}
    end.

clear_pem_cache() ->
    case erltls_manager:clear_cache() of
        true ->
            ok;
        Error ->
            {error, Error}
    end.

connect(Socket, SslOptions) when is_port(Socket) ->
    erltls_ssl_process:new(Socket, SslOptions, ?SSL_ROLE_CLIENT).

connect(Host, Port, Options) ->
    connect(Host, Port, Options, infinity).

connect(Host, Port, Options, Timeout) ->
    {TcpOpt, TlsOpt} = get_options(Options),
    case gen_tcp:connect(Host, Port, TcpOpt, Timeout) of
        {ok, TcpSocket} ->
            erltls_ssl_process:new(TcpSocket, TlsOpt, ?SSL_ROLE_CLIENT);
        Error ->
            Error
    end.

controlling_process(#tlssocket{ssl_pid = Pid}, NewOwner) ->
    erltls_ssl_process:controlling_process(Pid, NewOwner).

getopts(#tlssocket{tcp_sock = TcpSock}, OptionNames) ->
    inet:getopts(TcpSock, OptionNames).

setopts(#tlssocket{tcp_sock = TcpSock}, Options) ->
    inet:setopts(TcpSock, Options).

getstat(#tlssocket{tcp_sock = TcpSock}) ->
    inet:getstat(TcpSock).

getstat(#tlssocket{tcp_sock = TcpSock}, Opt) ->
    inet:getstat(TcpSock, Opt).

peername(#tlssocket{tcp_sock = TcpSock}) ->
    inet:peername(TcpSock).

listen(Port, Options) ->
    {TcpOpt, TlsOpt} = get_options(Options),
    case gen_tcp:listen(Port, TcpOpt) of
        {ok, TcpSocket} ->
             case erltls_ssl_process:new(TcpSocket, TlsOpt, ?SSL_ROLE_SERVER) of
                 {ok, SocketRef} ->
                     {ok, SocketRef#tlssocket{tls_opt = TlsOpt}};
                 Error ->
                     Error
             end;
        Error ->
            Error
    end.

transport_accept(ListenSocket) ->
    transport_accept(ListenSocket, infinity).

transport_accept(#tlssocket{tcp_sock = TcpSock, tls_opt = TlsOpt}, Timeout) ->
    case gen_tcp:accept(TcpSock, Timeout) of
        {ok, ASocket} ->
            erltls_ssl_process:new(ASocket, TlsOpt, ?SSL_ROLE_SERVER);
        UnexpectedError ->
            UnexpectedError
    end.

ssl_accept(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}) ->
    erltls_ssl_process:handshake(Pid, TcpSock).

send(#tlssocket{ssl_pid = Pid, tcp_sock = TcpSocket}, Data) ->
    case erltls_ssl_process:encode_data(Pid, Data) of
        {ok, TlsData} ->
            gen_tcp:send(TcpSocket, TlsData);
        Error ->
            Error
    end.

recv(Socket, Length) ->
    recv(Socket, Length, infinity).

recv(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}, Length, Timeout) ->
    case gen_tcp:recv(TcpSock, Length, Timeout) of
        {ok, Packet} ->
            erltls_ssl_process:decode_data(Pid, Packet);
        Error ->
            Error
    end.

close(#tlssocket{ssl_pid = Pid, tcp_sock = TcpSocket}) ->
    case catch erltls_ssl_process:shutdown(Pid) of
        ok ->
            ok;
        BytesWrite when is_binary(BytesWrite) ->
            gen_tcp:send(TcpSocket, BytesWrite);
        Error ->
            ?ERROR_MSG("shutdown unexpected error:~p", [Error])
    end,

    erltls_ssl_process:close(Pid),
    gen_tcp:close(TcpSocket).

%internals

get_options(Options) ->
    get_options(Options, [], []).

get_options([], TcpOpt, TlsOpt) ->
    {TcpOpt, TlsOpt};
get_options([H|T], TcpOpt, TlsOpt) ->
    case is_tls_option(H) of
        true ->
            get_options(T, TcpOpt, [H|TlsOpt]);
        _ ->
            get_options(T, [H|TcpOpt], TlsOpt)
    end.

is_tls_option({certfile, _}) ->
    true;
is_tls_option({dhfile, _}) ->
    true;
is_tls_option({cacerts, _}) ->
    true;
is_tls_option({ciphers, _}) ->
    true;
is_tls_option({verify, _}) ->
    true;
is_tls_option({compression, _}) ->
    true;
is_tls_option(_) ->
    false.
