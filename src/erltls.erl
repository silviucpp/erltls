-module(erltls).
-author("silviu.caragea").

-include("erltls.hrl").

%% todo:
%% 1. implement the missing methods
%% 2. In handshake process add a timeout param (affects connect and ssl_accept methods)
%% 3. write a test for upgrading from tcp to tls
%% 4. write a test for downgrading from tls to tcp

-export([
    start/0,
    start/1,
    stop/0,
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
    sockname/1,
    listen/2,
    transport_accept/1,
    transport_accept/2,
    ssl_accept/1,
    ssl_accept/2,
    ssl_accept/3,
    send/2,
    recv/2,
    recv/3,
    close/1
]).

-spec start() -> ok  | {error, reason()}.

start() ->
    start(temporary).

-spec start(permanent | transient | temporary) -> ok | {error, reason()}.

start(Type) ->
    case application:ensure_all_started(erltls, Type) of
        {ok, _} ->
            ok;
        Other ->
            Other
    end.

-spec stop() -> ok.

stop() ->
    application:stop(erltls).

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

-spec connect(port(), [connect_option()]) ->
    {ok, tlssocket()} | {error, reason()}.

connect(Socket, SslOptions) ->
    connect(Socket, SslOptions, infinity).

-spec connect(port() | host(), [connect_option()] | inet:port_number(), timeout() | list()) ->
    {ok, tlssocket()} | {error, reason()}.

connect(Socket, SslOptions, _Timeout) when is_port(Socket) ->
    %todo: implement timeout in this case
    case erltls_options:get_options(SslOptions) of
        {ok, [], TlsOpt, []} ->
            erltls_ssl_process:new(Socket, TlsOpt, erltls_options:default_emulated(), ?SSL_ROLE_CLIENT);
        {ok, TcpOpt, _TlsOpt, EmulatedOpt} ->
            {error, {options, TcpOpt ++ EmulatedOpt}};
        Error ->
            Error
    end;
connect(Host, Port, Options) ->
    connect(Host, Port, Options, infinity).

-spec connect(host(), inet:port_number(), [connect_option()], timeout()) ->
    {ok, tlssocket()} | {error, reason()}.

connect(Host, Port, Options, Timeout) ->
    case erltls_options:get_options(Options) of
        {ok, TcpOpt, TlsOpt, EmulatedOpts} ->
            case gen_tcp:connect(Host, Port, TcpOpt, Timeout) of
                {ok, TcpSocket} ->
                    erltls_ssl_process:new(TcpSocket, TlsOpt, EmulatedOpts, ?SSL_ROLE_CLIENT);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec controlling_process(tlssocket(), pid()) ->
    ok | {error, reason()}.

controlling_process(#tlssocket{ssl_pid = Pid}, NewOwner) ->
    erltls_ssl_process:controlling_process(Pid, NewOwner).

-spec getopts(tlssocket(), [gen_tcp:option_name()]) ->
    {ok, [gen_tcp:option()]} | {error, reason()}.

getopts(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}, OptionNames) ->
    case erltls_options:get_inet_names(OptionNames) of
        {ok, InetOptsNames, []} ->
            inet:getopts(TcpSock, InetOptsNames);
        {ok, [], EmulatedOptsNames} ->
            erltls_ssl_process:get_emulated_options(Pid, EmulatedOptsNames);
        {ok, InetOptsNames, EmulatedOptsNames} ->
            case inet:getopts(TcpSock, InetOptsNames) of
                {ok, Opts1} ->
                    case erltls_ssl_process:get_emulated_options(Pid, EmulatedOptsNames) of
                        {ok, Opts2} ->
                            {ok, Opts1 ++ Opts2};
                        Error ->
                            Error
                    end;
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec setopts(tlssocket(),  [gen_tcp:option()]) ->
    ok | {error, reason()}.

setopts(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}, Options) ->
    case erltls_options:get_inet_options(Options) of
        {ok, InetOpts, EmulatedOpts} ->
            case set_inet_opts(TcpSock, InetOpts) of
                ok ->
                    erltls_ssl_process:set_emulated_options(Pid, EmulatedOpts);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec getstat(tlssocket()) ->
    {ok, [{inet:stat_option(), integer()}]} | {error, inet:posix()}.

getstat(#tlssocket{tcp_sock = TcpSock}) ->
    inet:getstat(TcpSock).

-spec getstat(tlssocket(), [inet:stat_option()]) ->
    {ok, [{inet:stat_option(), integer()}]} | {error, inet:posix()}.

getstat(#tlssocket{tcp_sock = TcpSock}, Opt) ->
    inet:getstat(TcpSock, Opt).

-spec peername(tlssocket()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, reason()}.

peername(#tlssocket{tcp_sock = TcpSock}) ->
    inet:peername(TcpSock).

-spec sockname(tlssocket()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, reason()}.

sockname(#tlssocket{tcp_sock = TcpSock}) ->
    inet:sockname(TcpSock).

-spec listen(inet:port_number(), [listen_option()]) ->
    {ok, tlssocket()} | {error, reason()}.

listen(Port, Options) ->
    case erltls_options:get_options(Options) of
        {ok, TcpOpt, TlsOpt, EmulatedOpt} ->
            case gen_tcp:listen(Port, TcpOpt) of
                {ok, TcpSocket} ->
                    erltls_ssl_process:new(TcpSocket, TlsOpt, EmulatedOpt, ?SSL_ROLE_SERVER);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec transport_accept(tlssocket()) ->
    {ok, tlssocket()} |{error, reason()}.

transport_accept(ListenSocket) ->
    transport_accept(ListenSocket, infinity).

-spec transport_accept(tlssocket(), timeout()) ->
    {ok, tlssocket()} | {error, reason()}.

transport_accept(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}, Timeout) ->
    case gen_tcp:accept(TcpSock, Timeout) of
        {ok, ASocket} ->
            case erltls_ssl_process:get_options(Pid) of
                {ok, TlsOpts, EmulatedOpts} ->
                    erltls_ssl_process:new(ASocket, TlsOpts, EmulatedOpts, ?SSL_ROLE_SERVER);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec ssl_accept(tlssocket()) -> ok | {error, reason()}.

ssl_accept(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}) ->
    erltls_ssl_process:handshake(Pid, TcpSock).

-spec ssl_accept(tlssocket() | port(), timeout()| [tls_option()]) ->
    ok | {ok, tlssocket()} | {error, reason()}.

ssl_accept(Socket, SslOptions) when is_list(SslOptions)->
    %todo: implement setting ssl options in this case
    ssl_accept(Socket);
ssl_accept(Socket, _Timeout)  ->
    %todo: implement timeout in this case
    ssl_accept(Socket).

-spec ssl_accept(tlssocket() | port(), [tls_option()], timeout()) ->
    {ok, tlssocket()} | {error, reason()}.

ssl_accept(Socket, SslOptions, _Timeout) when is_port(Socket) ->
    %todo: implement timeout in this case
    case erltls_options:get_options(SslOptions) of
        {ok, [], TlsOpt, []} ->
            case erltls_ssl_process:new(Socket, TlsOpt, erltls_options:default_emulated(), ?SSL_ROLE_SERVER) of
                {ok, SslSocket} ->
                    case erltls_ssl_process:handshake(SslSocket#tlssocket.ssl_pid, Socket) of
                        ok ->
                            {ok, SslSocket};
                        Error ->
                            Error
                    end;
                Error ->
                    Error
            end;
        {ok, TcpOpt, _TlsOpt, EmulatedOpt} ->
            {error, {options, TcpOpt ++ EmulatedOpt}};
        Error ->
            Error
    end;
ssl_accept(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}, _SslOptions, _Timeout) ->
    erltls_ssl_process:handshake(Pid, TcpSock).

-spec send(tlssocket(), iodata()) -> ok | {error, reason()}.

send(#tlssocket{ssl_pid = Pid, tcp_sock = TcpSocket}, Data) ->
    case erltls_ssl_process:encode_data(Pid, Data) of
        {ok, TlsData} ->
            gen_tcp:send(TcpSocket, TlsData);
        Error ->
            Error
    end.

-spec recv(tlssocket(), integer()) -> {ok, binary()| list()} | {error, reason()}.

recv(Socket, Length) ->
    recv(Socket, Length, infinity).

-spec recv(tlssocket(), integer(), timeout()) -> {ok, binary()| list()} | {error, reason()}.

recv(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}, Length, Timeout) ->
    case gen_tcp:recv(TcpSock, Length, Timeout) of
        {ok, Packet} ->
            erltls_ssl_process:decode_data(Pid, Packet);
        Error ->
            Error
    end.

-spec close(tlssocket()) -> term().

close(#tlssocket{ssl_pid = Pid, tcp_sock = TcpSocket}) ->
    erltls_ssl_process:shutdown(Pid),
    gen_tcp:close(TcpSocket).

%internals

set_inet_opts(_TcpSock, []) ->
    ok;
set_inet_opts(TcpSock, Options) ->
    inet:setopts(TcpSock, Options).