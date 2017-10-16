-module(erltls).

-include("erltls.hrl").

%% todo:
%% 1. implement the missing methods
%% 2. In handshake process add a timeout param (affects connect and ssl_accept methods)

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
    peercert/1,
    connection_information/1,
    peername/1,
    sockname/1,
    session_reused/1,
    listen/2,
    transport_accept/1,
    transport_accept/2,
    ssl_accept/1,
    ssl_accept/2,
    ssl_accept/3,
    send/2,
    recv/2,
    recv/3,
    close/1,
    close/2,
    shutdown/2,
    versions/0
]).

-spec start() ->
    ok  | {error, reason()}.

start() ->
    start(temporary).

-spec start(permanent | transient | temporary) ->
    ok | {error, reason()}.

start(Type) ->
    case application:ensure_all_started(erltls, Type) of
        {ok, _} ->
            ok;
        Other ->
            Other
    end.

-spec stop() ->
    ok.

stop() ->
    application:stop(erltls).

cipher_suites() ->
    case erltls_manager:get_context([], false) of
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

connect(Socket, TlsOpt) ->
    connect(Socket, TlsOpt, ?DEFAULT_TIMEOUT).

-spec connect(port() | host(), [connect_option()] | inet:port_number(), timeout() | list()) ->
    {ok, tlssocket()} | {error, reason()}.

connect(Socket, TlsOpt0, Timeout) when is_port(Socket) ->
    %todo: implement timeout in this case

    case inet:setopts(Socket, erltls_options:default_inet_options()) of
        ok ->
            case erltls_options:get_options(TlsOpt0) of
                {ok, [], TlsOpt, []} ->
                    do_connect(Socket, TlsOpt, erltls_options:emulated_for_socket(Socket), Timeout);
                {ok, TcpOpt, _TlsOpt, EmulatedOpt} ->
                    {error, {options, TcpOpt ++ EmulatedOpt}};
                Error ->
                    Error
            end;
        Error ->
            Error
    end;

connect(Host, Port, Options) ->
    connect(Host, Port, Options, ?DEFAULT_TIMEOUT).

-spec connect(host(), inet:port_number(), [connect_option()], timeout()) ->
    {ok, tlssocket()} | {error, reason()}.

connect(Host, Port, Options, Timeout) ->
    case erltls_options:get_options(Options) of
        {ok, TcpOpt, TlsOpt, EmulatedOpts} ->
            case gen_tcp:connect(Host, Port, TcpOpt ++ erltls_options:default_inet_options(), Timeout) of
                {ok, TcpSocket} ->
                    do_connect(TcpSocket, TlsOpt, EmulatedOpts, Timeout);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec controlling_process(tlssocket(), pid()) ->
    ok | {error, reason()}.

controlling_process(#tlssocket{ssl_pid = Pid} = Socket, NewOwner) ->
    erltls_ssl_process:controlling_process(Pid, Socket, NewOwner).

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

setopts(#tlssocket{ssl_pid = Pid}, Options) ->
    case erltls_options:get_inet_options(Options) of
        {ok, InetOpts, EmulatedOpts} ->
            erltls_ssl_process:setopts(Pid, InetOpts, EmulatedOpts);
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

-spec peercert(tlssocket()) ->
    {ok, binary()} | {error, reason()}.

peercert(#tlssocket{ssl_pid = Pid}) ->
    erltls_ssl_process:peercert(Pid).

-spec peername(tlssocket()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, reason()}.

peername(#tlssocket{tcp_sock = TcpSock}) ->
    inet:peername(TcpSock).

-spec sockname(tlssocket()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, reason()}.

sockname(#tlssocket{tcp_sock = TcpSock}) ->
    inet:sockname(TcpSock).

-spec connection_information(tlssocket()) -> {ok, list()} | {error, reason()}.

connection_information(#tlssocket{ssl_pid = Pid}) ->
    erltls_ssl_process:session_info(Pid).

-spec session_reused(tlssocket()) -> boolean() | {error, reason()}.

session_reused(#tlssocket{ssl_pid = Pid}) ->
    erltls_ssl_process:session_reused(Pid).

-spec listen(inet:port_number(), [listen_option()]) ->
    {ok, tlssocket()} | {error, reason()}.

listen(Port, Options) ->
    case erltls_options:get_options(Options) of
        {ok, TcpOpt, TlsOpt, EmulatedOpt} ->
            case gen_tcp:listen(Port, TcpOpt ++ erltls_options:default_inet_options()) of
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
    transport_accept(ListenSocket, ?DEFAULT_TIMEOUT).

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

-spec ssl_accept(tlssocket()) ->
    ok | {error, reason()}.

ssl_accept(Socket) ->
    ssl_accept(Socket, ?DEFAULT_TIMEOUT).

-spec ssl_accept(tlssocket() | port(), timeout()| [tls_option()]) ->
    ok | {ok, tlssocket()} | {error, reason()}.

ssl_accept(#tlssocket{} = Socket, Timeout) ->
    ssl_accept(Socket, [], Timeout);
ssl_accept(Socket, SslOptions) when is_port(Socket) ->
    ssl_accept(Socket, SslOptions, ?DEFAULT_TIMEOUT).

-spec ssl_accept(tlssocket() | port(), [tls_option()], timeout()) ->
    {ok, tlssocket()} | {error, reason()}.

ssl_accept(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}, [], Timeout) ->
    erltls_ssl_process:handshake(Pid, TcpSock, Timeout);
ssl_accept(Socket, SslOptions, Timeout) when is_port(Socket) ->
    case erltls_options:get_options(SslOptions) of
        {ok, [], TlsOpt, []} ->
            case erltls_ssl_process:new(Socket, TlsOpt, erltls_options:emulated_for_socket(Socket), ?SSL_ROLE_SERVER) of
                {ok, SslSocket} ->
                    case erltls_ssl_process:handshake(SslSocket#tlssocket.ssl_pid, Socket, Timeout) of
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
    end.

-spec send(tlssocket(), iodata()) ->
    ok | {error, reason()}.

send(#tlssocket{ssl_pid = Pid, tcp_sock = TcpSocket}, Data) ->
    case erltls_ssl_process:encode_data(Pid, Data) of
        {ok, TlsData} ->
            gen_tcp:send(TcpSocket, TlsData);
        Error ->
            Error
    end.

-spec recv(tlssocket(), integer()) ->
    {ok, binary()| list()} | {error, reason()}.

recv(Socket, Length) ->
    recv(Socket, Length, infinity).

-spec recv(tlssocket(), integer(), timeout()) ->
    {ok, binary()| list()} | {error, reason()}.

recv(#tlssocket{tcp_sock = TcpSock, ssl_pid = Pid}, Length, Timeout) ->
    case erltls_ssl_process:get_pending_buffer(Pid, Length) of
        need_more ->
            passive_read_more(TcpSock, Pid, Length, Timeout);
        Response->
            Response
    end.

passive_read_more(TcpSock, TlsPid, TotalLength, Timeout) ->
    case gen_tcp:recv(TcpSock, 0, Timeout) of
        {ok, Packet} ->
            case erltls_ssl_process:decode_data(TlsPid, Packet, TotalLength) of
                need_more ->
                    passive_read_more(TcpSock, TlsPid, TotalLength, Timeout);
                Response  ->
                    Response
            end;
        Error ->
            Error
    end.

-spec close(tlssocket(), timeout() | {pid(), integer()}) ->
    ok | {ok, port()} | {error, reason()}.

close(#tlssocket{tcp_sock = TcpSock, ssl_pid = SslPid} = Socket, {NewOwnerPid, Timeout}) when is_pid(NewOwnerPid) ->
    case erltls_ssl_process:downgrade(SslPid, NewOwnerPid, Timeout) of
        ok ->
            {ok, TcpSock};
        Error ->
            close(Socket),
            Error
    end;
close(TlsSocket, _Timeout) ->
    %todo: implement timeout parameter here.
    close(TlsSocket).

-spec close(tlssocket()) -> term().

close(#tlssocket{ssl_pid = Pid, tcp_sock = TcpSocket}) ->
    erltls_ssl_process:shutdown(Pid),
    erltls_ssl_process:close(Pid),
    gen_tcp:close(TcpSocket).

-spec shutdown(tlssocket(), read | write | read_write) ->
    ok | {error, reason()}.

shutdown(#tlssocket{tcp_sock = TcpSocket, ssl_pid = Pid}, How)->
    case How =:= write orelse How =:= read_write of
        true ->
            erltls_ssl_process:shutdown(Pid);
        _ ->
            ok
    end,
    gen_tcp:shutdown(TcpSocket, How).

-spec versions() ->
    {ok, list()}.

versions() ->
    erltls_nif:version().

%internals

do_connect(TcpSocket, TlsOpt, EmulatedOpts, Timeout) when is_list(EmulatedOpts) ->
    UseSessionTicket = erltls_options:use_session_ticket(erltls_utils:lookup(use_session_ticket, TlsOpt)),

    case get_session_ticket(UseSessionTicket, TcpSocket) of
        {ok, SessionAsn1, Host, Port} ->
            case erltls_ssl_process:new(TcpSocket, TlsOpt, EmulatedOpts, ?SSL_ROLE_CLIENT, SessionAsn1, Timeout) of
                {ok, #tlssocket{ssl_pid = Pid} = TlsSocketRef} ->
                    update_session_ticket(UseSessionTicket, Host, Port, Pid),
                    {ok, TlsSocketRef};
                Error ->
                    Error
            end;
        Error ->
            Error
    end;
do_connect(_TcpSocket, _TlsOpt, EmulatedOpts, _Timeout) ->
    {error, EmulatedOpts}.

get_session_ticket(true, Socket) ->
    case inet:peername(Socket) of
        {ok, {Host, Port}} ->
            case erltls_ticket_cache:get(Host, Port) of
                null ->
                    {ok, <<>>, Host, Port};
                {ok, SessionAsn1} ->
                    {ok, SessionAsn1, Host, Port};
                Resp ->
                    Resp
            end;
        Error ->
            Error
    end;
get_session_ticket(_, _Socket) ->
    {ok, <<>>, undefined, undefined}.

update_session_ticket(true, Host, Port, TlsRef) ->
    case erltls_ssl_process:get_session_asn1(TlsRef) of
        {ok, HasTicket, SessionAsn1} ->
            case HasTicket of
                true ->
                    erltls_ticket_cache:set(Host, Port, SessionAsn1);
                _ ->
                    true
            end;
        Error ->
            Error
    end;
update_session_ticket(_, _Host, _Port, _TlsRef) ->
    true.

