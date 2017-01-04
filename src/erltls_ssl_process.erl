-module(erltls_ssl_process).
-author("silviu.caragea").

-include("erltls.hrl").

-behaviour(gen_server).

-define(VERIFY_NONE, 1).
-define(COMPRESSION_NONE, 2).
-define(SESSION_TICKET, 4).

-define(SERVER, ?MODULE).

-define(PENDING_DATA_INTERVAL, 10).

-record(state, {
    tcp,
    tls_ref,
    tls_opts,
    emul_opts = #emulated_opts{},
    owner_pid,
    owner_monitor_ref,
    tcp_monitor_ref,
    hk_completed = false,
    socket_ref,
    pending_buffer = <<>>
}).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-export([
    new/4,
    new/5,
    setopts/3,
    get_options/1,
    get_emulated_options/2,
    controlling_process/2,
    handshake/2,
    encode_data/2,
    decode_data/2,
    shutdown/1,
    session_reused/1,
    get_session_asn1/1,
    get_pending_data/1
]).

new(TcpSocket, TlsOptions, EmulatedOpts, Role) ->
    new(TcpSocket, TlsOptions, EmulatedOpts, Role, <<>>).

new(TcpSocket, TlsOptions, EmulatedOpts, Role, CachedSession) ->
    case erltls_manager:get_context(TlsOptions, mandatory_cert(Role)) of
        {ok, Context} ->
            case erltls_nif:ssl_new(Context, Role, get_ssl_flags(TlsOptions), CachedSession) of
                {ok, TlsSock} ->
                    get_ssl_process(Role, TcpSocket, TlsSock, TlsOptions, EmulatedOpts);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

get_options(Pid) ->
    call(Pid, get_options).

get_emulated_options(Pid, OptionNames) ->
    call(Pid, {get_emulated_options, OptionNames}).

controlling_process(Pid, NewOwner) ->
    call(Pid, {controlling_process, self(), NewOwner}).

handshake(Pid, TcpSocket) ->
    call(Pid, {handshake, TcpSocket}).

encode_data(Pid, Data) ->
    call(Pid, {encode_data, Data}).

decode_data(Pid, Data) ->
    call(Pid, {decode_data, Data}).

session_reused(Pid) ->
    call(Pid, session_reused).

get_session_asn1(Pid) ->
    call(Pid, get_session_asn1).

shutdown(Pid) ->
    call(Pid, shutdown).

get_pending_data(Pid) ->
    call(Pid, get_pending_data).

setopts(Pid, InetOpts, EmulatedOpts) ->
    call(Pid, {setopts, InetOpts, EmulatedOpts}).

%internals for gen_server

init(#state{tcp = TcpSocket} = State) ->
    TcpMonitorRef = erlang:monitor(port, TcpSocket),
    OwnerMonitorRef = erlang:monitor(process, State#state.owner_pid),
    SocketRef = #tlssocket{tcp_sock = TcpSocket, ssl_pid = self()},
    {ok, State#state{owner_monitor_ref = OwnerMonitorRef, tcp_monitor_ref = TcpMonitorRef, socket_ref = SocketRef}}.

handle_call({encode_data, Data}, _From, #state{tls_ref = TlsSock} = State) ->
    {reply, erltls_nif:ssl_send_data(TlsSock, Data), State};

handle_call({decode_data, TlsData}, _From, #state{tls_ref = TlsSock, emul_opts = EmulOpts} = State) ->
    Response = case erltls_nif:ssl_feed_data(TlsSock, TlsData) of
        {ok, Data} ->
            {ok, convert_data(EmulOpts#emulated_opts.mode, Data)};
        Error ->
            Error
    end,
    {reply, Response, State};

handle_call({setopts, InetOpts, NewEmulatedOpts}, _From, #state{tcp = TcpSock, emul_opts = EmulatedOps, pending_buffer = Pb} = State) ->
    case set_inet_opts(TcpSock, InetOpts) of
        ok ->
            % in case we have pending data and socket is active we send it
            case byte_size(Pb) > 0 of
                true ->
                    case erltls_utils:lookup(active, TcpSock, false) of
                        false ->
                            ok;
                        _ ->
                            erlang:send_after(?PENDING_DATA_INTERVAL, self(), send_pending_data)
                    end;
                _ ->
                    ok
            end,

            case NewEmulatedOpts of
                [] ->
                    {reply, ok, State};
                _ ->
                    {reply, ok, State#state{emul_opts = erltls_options:emulated_list2record(NewEmulatedOpts, EmulatedOps)}}
            end;
        Error ->
            {reply, Error, State}
    end;

handle_call(get_pending_data, _From, #state{pending_buffer = PendingBuff} = State) ->
    {reply, PendingBuff, State#state {pending_buffer = <<>>}};

handle_call(get_options, _From, #state{emul_opts = EmulatedOpts, tls_opts = TlsOpts} = State) ->
    {reply, {ok, TlsOpts, erltls_options:emulated_record2list(EmulatedOpts)}, State};

handle_call({get_emulated_options, OptionNames}, _From, #state{emul_opts = EmulatedOpts} = State) ->
    {reply, {ok, erltls_options:emulated_by_names(OptionNames, EmulatedOpts)}, State};

handle_call({controlling_process, SenderPid, NewOwner}, _From, State) ->
    #state{owner_pid = OwnerPid, owner_monitor_ref = OwnerMonitRef} = State,

    case SenderPid =:= OwnerPid of
        true ->
            case OwnerMonitRef of
                undefined ->
                    ok;
                _ ->
                    erlang:demonitor(OwnerMonitRef)
            end,
            NewOwnerRef = erlang:monitor(process, NewOwner),
            {reply, ok, State#state {owner_pid = NewOwner, owner_monitor_ref = NewOwnerRef}};
        _ ->
            {reply, {error, not_owner}, State}
    end;

handle_call({handshake, TcpSocket}, _From, #state{tls_ref = TlsSock} = State) ->
    case State#state.hk_completed of
        true ->
            {reply, {error, <<"handshake already completed">>}, State};
        _ ->
            case inet:getopts(TcpSocket, [active]) of
                {ok, [{active, CurrentMode}]} ->
                    change_active(TcpSocket, CurrentMode, false),
                    case do_handshake(TcpSocket, TlsSock) of
                        ok ->
                            change_active(TcpSocket, CurrentMode, false),

                            case erltls_nif:ssl_feed_data(TlsSock, <<>>) of
                                {ok, PendingBuff} ->

                                    case PendingBuff of
                                        <<>> ->
                                            ok;
                                        _ ->
                                            erlang:send_after(?PENDING_DATA_INTERVAL, self(), send_pending_data)
                                    end,

                                    {reply, ok, State#state{hk_completed = true, pending_buffer = PendingBuff}};
                                Error ->
                                    Error
                            end;
                        Error ->
                            change_active(TcpSocket, CurrentMode, false),
                            {reply, Error, State}
                    end;
                Error ->
                    Error
            end
    end;

handle_call(get_session_asn1, _From, #state{tls_ref = TlsRef} = State) ->
    {reply, erltls_nif:ssl_get_session_asn1(TlsRef), State};

handle_call(session_reused, _From, #state{tls_ref = TlsRef} = State) ->
    {reply, erltls_nif:ssl_session_reused(TlsRef), State};

handle_call(shutdown, _From, #state{tcp = TcpSocket, tls_ref = TlsRef} = State) ->
    {stop, normal, shutdown_ssl(TcpSocket, TlsRef), State};

handle_call(close, _From, State) ->
    {stop, normal, ok, State};

handle_call(Request, _From, State) ->
    ?ERROR_MSG("handle_call unknown request: ~p", [Request]),
    {noreply, State}.

handle_cast(Request, State) ->
    ?ERROR_MSG("handle_cast unknown request: ~p", [Request]),
    {noreply, State}.

handle_info({tcp, TcpSocket, TlsData}, #state{tcp = TcpSocket, tls_ref = TlsRef, owner_pid = Pid, socket_ref = SockRef, emul_opts = EmOpt, pending_buffer = Pb} = State) ->
    case erltls_nif:ssl_feed_data(TlsRef, TlsData) of
        {ok, RawData} ->
            Pid ! {ssl, SockRef, convert_data(EmOpt#emulated_opts.mode, get_buffer(Pb, RawData))};
        Error ->
            Pid ! {ssl_error, SockRef, Error}
    end,
    {noreply, State#state {pending_buffer = <<>>}};

handle_info({tcp_closed, TcpSocket}, #state{tcp = TcpSocket, owner_pid = Pid, socket_ref = SockRef} = State) ->
    Pid ! {ssl_closed, SockRef},
    {stop, normal, State};

handle_info({tcp_error, TcpSocket, Reason}, #state{tcp = TcpSocket, owner_pid = Pid, socket_ref = SockRef} = State) ->
    Pid ! {ssl_error, SockRef, Reason},
    {noreply, State};

handle_info({tcp_passive, TcpSocket}, #state{tcp = TcpSocket, owner_pid = Pid, socket_ref = SockRef} = State) ->
    Pid ! {ssl_passive, SockRef},
    {noreply, State};

handle_info(send_pending_data, #state{tcp = TcpSocket, tls_ref = TlsRef, pending_buffer = PendingBuffer, owner_pid = Pid, socket_ref = SockRef, emul_opts = EmOpt} = State) ->
    case PendingBuffer of
        <<>> ->
            ok;
        _ ->
            case inet:getopts(TcpSocket, [active]) of
                {ok, [{active, false}]} ->
                    ok;
                {ok, [{active, Active}]} ->
                    case Active of
                        true ->
                            ok;
                        once ->
                            inet:setopts(TcpSocket, [{active, false}]);
                        N when is_integer(N) ->
                            inet:setopts(TcpSocket, [{active, N-1}])
                    end,

                    case pop_active_message(TcpSocket, TlsRef, PendingBuffer) of
                        {ok, SendData} ->
                            Pid ! {ssl, SockRef, convert_data(EmOpt#emulated_opts.mode, SendData)};
                        Error ->
                            Pid ! {ssl_error, SockRef, Error}
                    end;
                Error ->
                    ?ERROR_MSG("failed to get socket active mode: ~p", [Error])
            end
    end,
    {noreply, State#state {pending_buffer = <<>>}};

handle_info({'DOWN', MonitorRef, _, _, _}, State) ->
    #state{tcp = TcpSocket, tls_ref = TlsRef, owner_monitor_ref = OwnerMonitorRef, tcp_monitor_ref = TcpMonitorRef} = State,

    case MonitorRef of
        OwnerMonitorRef ->
            shutdown_ssl(TcpSocket, TlsRef),
            gen_tcp:close(TcpSocket),
            {stop, normal, State};
        TcpMonitorRef ->
            {stop, normal, State};
        _ ->
            {noreply, State}
    end;

handle_info(Request, State) ->
    ?ERROR_MSG("handle_info unknown request: ~p", [Request]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

call(Pid, Message) ->
    try
        gen_server:call(Pid, Message)
    catch
        exit:{noproc, _} ->
            {error, ssl_not_started};
        _: Exception ->
            {error, Exception}
    end.

%internal methods

get_verify(verify_none) ->
    ?VERIFY_NONE;
get_verify(_) ->
    0.

get_compression(compression_none) ->
    ?COMPRESSION_NONE;
get_compression(_) ->
    0.

get_session_ticket(true) ->
    ?SESSION_TICKET;
get_session_ticket(_) ->
    0.

get_ssl_flags(Options) ->
    VerifyType = get_verify(erltls_utils:lookup(verify, Options)),
    CompressionType = get_compression(erltls_utils:lookup(compression, Options)),
    UseSessionTicket = get_session_ticket(erltls_options:use_session_ticket(erltls_utils:lookup(use_session_ticket, Options))),
    VerifyType bor CompressionType bor UseSessionTicket.

get_ssl_process(?SSL_ROLE_SERVER, TcpSocket, TlsSock, TlsOpts, EmulatedOpts) ->
    start_link(TcpSocket, TlsSock, TlsOpts, EmulatedOpts, false, <<>>);
get_ssl_process(?SSL_ROLE_CLIENT, TcpSocket, TlsSock, TlsOpts, EmulatedOpts) ->
    case inet:getopts(TcpSocket, [active]) of
        {ok, [{active, CurrentMode}]} ->
            change_active(TcpSocket, CurrentMode, false),
            case do_handshake(TcpSocket, TlsSock) of
                ok ->
                    change_active(TcpSocket, false, CurrentMode),

                    case erltls_nif:ssl_feed_data(TlsSock, <<>>) of
                        {ok, PendingBuff} ->
                            start_link(TcpSocket, TlsSock, TlsOpts, EmulatedOpts, true, PendingBuff);
                        Error ->
                            Error
                    end;
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

start_link(TcpSocket, TlsSock, TlsOpts, EmulatedOpts, HkCompleted, PendingBuf) ->
    State = #state{
        tcp = TcpSocket,
        tls_ref = TlsSock,
        owner_pid = self(),
        hk_completed = HkCompleted,
        pending_buffer = PendingBuf,
        emul_opts = erltls_options:emulated_list2record(EmulatedOpts),
        tls_opts = TlsOpts
    },

    case gen_server:start_link(?MODULE, State, []) of
        {ok, Pid} ->
            case gen_tcp:controlling_process(TcpSocket, Pid) of
                ok ->
                    case PendingBuf of
                        <<>> ->
                            ok;
                        _ ->
                            erlang:send_after(?PENDING_DATA_INTERVAL, self(), send_pending_data)
                    end,

                    {ok, #tlssocket{tcp_sock = TcpSocket, ssl_pid = Pid}};
                Error ->
                    stop_process(Pid),
                    Error
            end;
        Error ->
            Error
    end.

change_active(_TcpSocket, CurrentMode, NewMode) when CurrentMode =:= NewMode ->
    ok;
change_active(TcpSocket, _CurrentMode, NewMode) ->
    inet:setopts(TcpSocket, [{active, NewMode}]).

do_handshake(TcpSocket, TlsSock) ->
    case erltls_nif:ssl_handshake(TlsSock) of
        {ok, 1} ->
            send_pending(TcpSocket, TlsSock);
        {ok, 0} ->
            send_pending(TcpSocket, TlsSock),
            {error, <<"handshake failed">>};
        {error, ?SSL_ERROR_WANT_READ} ->
            case send_pending(TcpSocket, TlsSock) of
                ok ->
                    read_handshake(TcpSocket, TlsSock);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

read_handshake(TcpSocket, TlsSock) ->
    case gen_tcp:recv(TcpSocket, 0) of
        {ok, Packet} ->
            case erltls_nif:ssl_feed_data(TlsSock, Packet) of
                ok ->
                    do_handshake(TcpSocket, TlsSock);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

send_pending(TcpSocket, TlsSock) ->
    case erltls_nif:ssl_send_pending(TlsSock) of
        {ok, <<>>} ->
            ok;
        {ok, Data} ->
            gen_tcp:send(TcpSocket, Data)
    end.

shutdown_ssl(TcpSocket, TlsRef) ->
    case erltls_nif:ssl_shutdown(TlsRef) of
        {ok, Bytes} ->
            gen_tcp:send(TcpSocket, Bytes);
        ok ->
            ok;
        Error ->
            ?ERROR_MSG("shutdown unexpected error:~p", [Error]),
            Error
    end.

stop_process(Pid) ->
    call(Pid, close).

mandatory_cert(?SSL_ROLE_SERVER) ->
    true;
mandatory_cert(?SSL_ROLE_CLIENT) ->
    false.

get_buffer(<<>>, NewData) ->
    NewData;
get_buffer(Buffer, NewData) ->
    <<Buffer/binary, NewData/binary>>.

convert_data(binary, Data) ->
    Data;
convert_data(list, Data) ->
    binary_to_list(Data).

set_inet_opts(_TcpSock, []) ->
    ok;
set_inet_opts(TcpSock, Options) ->
    inet:setopts(TcpSock, Options).

pop_active_message(TcpSocket, TlsRef, Buffer) ->
    receive
        {tcp, TcpSocket, TlsData} ->
            case erltls_nif:ssl_feed_data(TlsRef, TlsData) of
                {ok, NewData} ->
                    {ok, <<Buffer/binary, NewData/binary>>};
                Error ->
                    Error
            end
        after 0 ->
            {ok, Buffer}
    end.