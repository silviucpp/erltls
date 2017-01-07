-module(erltls_ssl_process).
-author("silviu.caragea").

-include("erltls.hrl").

-behaviour(gen_server).

-define(USE_COMPRESSION_FLAG, 1).
-define(SESSION_TICKET_FLAG, 2).

-define(SERVER, ?MODULE).

-define(SSL_SHUTDOWN_UNIDIRECTIONAL, 1).
-define(SSL_SHUTDOWN_BIDIRECTIONAL, 2).

-record(state, {
    tcp,
    tls_ref,
    tls_opts,
    emul_opts = #emulated_opts{},
    owner_pid,
    owner_monitor_ref,
    tcp_monitor_ref,
    hk_completed = false,
    socket_ref
}).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-export([
    new/4,
    new/6,
    handshake/3,
    encode_data/2,
    decode_data/2,
    shutdown/1,
    downgrade/3,
    close/1,
    get_options/1,
    set_emulated_options/2,
    get_emulated_options/2,
    controlling_process/2,
    session_reused/1,
    get_session_asn1/1,
    peercert/1,
    protocol/1,
    session_info/1
]).

new(TcpSocket, TlsOptions, EmulatedOpts, Role) ->
    new(TcpSocket, TlsOptions, EmulatedOpts, Role, <<>>, infinity).

new(TcpSocket, TlsOptions, EmulatedOpts, Role, CachedSession, Timeout) ->
    case erltls_manager:get_context(TlsOptions, mandatory_cert(Role)) of
        {ok, Context} ->
            case erltls_nif:ssl_new(Context, Role, get_ssl_flags(TlsOptions), CachedSession) of
                {ok, TlsSock} ->
                    get_ssl_process(Role, TcpSocket, TlsSock, TlsOptions, EmulatedOpts, Timeout);
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

handshake(Pid, TcpSocket, Timeout) ->
    call(Pid, {handshake, TcpSocket, Timeout}).

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

downgrade(Pid, NewOwner, Timeout) ->
    call(Pid, {downgrade, NewOwner, Timeout}).

peercert(Pid) ->
    call(Pid, peercert).

set_emulated_options(_, []) ->
    ok;
set_emulated_options(Pid, Opts) ->
    call(Pid, {set_emulated_options, Opts}).

protocol(Pid) ->
    call(Pid, get_protocol).

session_info(Pid) ->
    call(Pid, get_session_info).

%internals for gen_server

init(#state{tcp = TcpSocket, tls_ref = TlsRef} = State) ->
    Self = self(),
    ok = erltls_nif:ssl_set_owner(TlsRef, Self),
    TcpMonitorRef = erlang:monitor(port, TcpSocket),
    OwnerMonitorRef = erlang:monitor(process, State#state.owner_pid),
    SocketRef = #tlssocket{tcp_sock = TcpSocket, ssl_pid = Self},
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

handle_call({set_emulated_options, Opts}, _From, #state{emul_opts = EmulatedOps} = State) ->
    {reply, ok, State#state{emul_opts = erltls_options:emulated_list2record(Opts, EmulatedOps)}};

handle_call(get_options, _From, #state{emul_opts = EmulatedOpts, tls_opts = TlsOpts} = State) ->
    {reply, {ok, TlsOpts, erltls_options:emulated_record2list(EmulatedOpts)}, State};

handle_call({get_emulated_options, OptionNames}, _From, #state{emul_opts = EmulatedOpts} = State) ->
    {reply, {ok, erltls_options:emulated_by_names(OptionNames, EmulatedOpts)}, State};

handle_call({controlling_process, SenderPid, NewOwner}, From, #state{socket_ref = SocketRef} = State) ->
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

            gen_server:reply(From, ok),
            SenderPid ! {erltls_message_transfer, SocketRef},
            receive
                {erltls_transfer_completed, SocketRef} ->
                    ok
                after 10000 ->
                    ok
            end,

            {noreply, State#state {owner_pid = NewOwner, owner_monitor_ref = NewOwnerRef}};
        _ ->
            {reply, {error, not_owner}, State}
    end;

handle_call({handshake, TcpSocket, Timeout}, _From, #state{tls_ref = TlsSock} = State) ->
    case State#state.hk_completed of
        true ->
            {reply, {error, <<"handshake already completed">>}, State};
        _ ->
            case inet:getopts(TcpSocket, [active]) of
                {ok, [{active, CurrentMode}]} ->
                    change_active(TcpSocket, CurrentMode, false),
                    case do_handshake(TcpSocket, TlsSock, Timeout) of
                        ok ->
                            change_active(TcpSocket, CurrentMode, false),
                            {reply, ok, State#state{hk_completed = true}};
                        Error ->
                            change_active(TcpSocket, CurrentMode, false),
                            {reply, Error, State}
                    end;
                Error ->
                    Error
            end
    end;

handle_call(peercert, _From, #state{tls_ref = TlsRef} = State) ->
    {reply, erltls_nif:ssl_peercert(TlsRef), State};

handle_call(get_session_asn1, _From, #state{tls_ref = TlsRef} = State) ->
    {reply, erltls_nif:ssl_get_session_asn1(TlsRef), State};

handle_call(session_reused, _From, #state{tls_ref = TlsRef} = State) ->
    {reply, erltls_nif:ssl_session_reused(TlsRef), State};

handle_call(shutdown, _From, #state{tcp = TcpSocket, tls_ref = TlsRef} = State) ->
    {reply, shutdown_ssl(TcpSocket, TlsRef), State};

handle_call({downgrade, NewOwner, Timeout}, _From, #state{tcp = TcpSocket, tls_ref = TlsRef} = State) ->
    case inet:setopts(TcpSocket, [{active, false}, {packet, 0}, {mode, binary}]) of
        ok ->
            case downgrade_ssl(TcpSocket, TlsRef, <<>>, Timeout) of
                ok ->
                    {stop, normal, inet_tcp:controlling_process(TcpSocket, NewOwner), State};
                Error ->
                    {reply, Error, State}
            end;
        Error ->
            {reply, Error, State}
    end;

handle_call(get_protocol, _From, #state{tls_ref = TlsRef} = State) ->
    {reply, erltls_nif:ssl_get_method(TlsRef), State};

handle_call(get_session_info, _From, #state{tls_ref = TlsRef} = State) ->
    {reply, erltls_nif:ssl_get_session_info(TlsRef), State};

handle_call(close, _From, State) ->
    {stop, normal, ok, State};

handle_call(Request, _From, State) ->
    ?ERROR_MSG("handle_call unknown request: ~p", [Request]),
    {noreply, State}.

handle_cast(Request, State) ->
    ?ERROR_MSG("handle_cast unknown request: ~p", [Request]),
    {noreply, State}.

handle_info({tcp, TcpSocket, TlsData}, #state{tcp = TcpSocket, tls_ref = TlsRef, owner_pid = Pid, socket_ref = SockRef, emul_opts = EmOpt} = State) ->
    case erltls_nif:ssl_feed_data(TlsRef, TlsData) of
        {ok, RawData} ->
            Pid ! {ssl, SockRef, convert_data(EmOpt#emulated_opts.mode, RawData)};
        Error ->
            Pid ! {ssl_error, SockRef, Error}
    end,
    {noreply, State};

handle_info({tcp_closed, TcpSocket}, #state{tcp = TcpSocket, owner_pid = Pid, socket_ref = SockRef} = State) ->
    Pid ! {ssl_closed, SockRef},
    {stop, normal, State};

handle_info({tcp_error, TcpSocket, Reason}, #state{tcp = TcpSocket, owner_pid = Pid, socket_ref = SockRef} = State) ->
    Pid ! {ssl_error, SockRef, Reason},
    {noreply, State};

handle_info({tcp_passive, TcpSocket}, #state{tcp = TcpSocket, owner_pid = Pid, socket_ref = SockRef} = State) ->
    Pid ! {ssl_passive, SockRef},
    {noreply, State};

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

get_compression(true) ->
    ?USE_COMPRESSION_FLAG;
get_compression(_) ->
    0.

get_session_ticket(true) ->
    ?SESSION_TICKET_FLAG;
get_session_ticket(_) ->
    0.

get_ssl_flags(Options) ->
    CompressionType = get_compression(erltls_utils:lookup(compression, Options, false)),
    UseSessionTicket = get_session_ticket(erltls_options:use_session_ticket(erltls_utils:lookup(use_session_ticket, Options))),
    CompressionType bor UseSessionTicket.

get_ssl_process(?SSL_ROLE_SERVER, TcpSocket, TlsSock, TlsOpts, EmulatedOpts, _Timeout) ->
    start_link(TcpSocket, TlsSock, TlsOpts, EmulatedOpts, false);
get_ssl_process(?SSL_ROLE_CLIENT, TcpSocket, TlsSock, TlsOpts, EmulatedOpts, Timeout) ->
    case inet:getopts(TcpSocket, [active]) of
        {ok, [{active, CurrentMode}]} ->
            change_active(TcpSocket, CurrentMode, false),
            case do_handshake(TcpSocket, TlsSock, Timeout) of
                ok ->
                    change_active(TcpSocket, false, CurrentMode),
                    start_link(TcpSocket, TlsSock, TlsOpts, EmulatedOpts, true);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

start_link(TcpSocket, TlsSock, TlsOpts, EmulatedOpts, HkCompleted) ->
    State = #state{
        tcp = TcpSocket,
        tls_ref = TlsSock,
        owner_pid = self(),
        hk_completed = HkCompleted,
        emul_opts = erltls_options:emulated_list2record(EmulatedOpts),
        tls_opts = TlsOpts
    },

    case gen_server:start_link(?MODULE, State, []) of
        {ok, Pid} ->
            case gen_tcp:controlling_process(TcpSocket, Pid) of
                ok ->
                    {ok, #tlssocket{tcp_sock = TcpSocket, ssl_pid = Pid}};
                Error ->
                    close(Pid),
                    Error
            end;
        Error ->
            Error
    end.

change_active(_TcpSocket, CurrentMode, NewMode) when CurrentMode =:= NewMode ->
    ok;
change_active(TcpSocket, _CurrentMode, NewMode) ->
    inet:setopts(TcpSocket, [{active, NewMode}]).

do_handshake(TcpSocket, TlsSock, Timeout) ->
    case erltls_nif:ssl_get_method(TlsSock) of
        {ok, Protocol} ->
            RecordHeaderSize = erltls_record:get_protocol_record_header_size(Protocol),
            do_handshake(TcpSocket, TlsSock, erltls_record:is_dtls(Protocol), RecordHeaderSize, Timeout);
        Error ->
            Error
    end.

do_handshake(TcpSocket, TlsSock, IsDtls, RecordHeaderSize, Timeout) ->
    case erltls_nif:ssl_handshake(TlsSock) of
        ok ->
            %handshake completed
            send_pending(TcpSocket, TlsSock);
        {error, ?SSL_ERROR_WANT_READ} ->
            case send_pending(TcpSocket, TlsSock) of
                ok ->
                    case erltls_record:read_next_record(TcpSocket, IsDtls, RecordHeaderSize, Timeout) of
                        {ok, _Type, Packet} ->
                            case erltls_nif:ssl_feed_data(TlsSock, Packet) of
                                ok ->
                                    do_handshake(TcpSocket, TlsSock, IsDtls, RecordHeaderSize, Timeout);
                                Error ->
                                    Error
                            end;
                        Error ->
                            Error
                    end;
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
    do_shutdown_ssl(TcpSocket, TlsRef, ?SSL_SHUTDOWN_UNIDIRECTIONAL, <<>>, infinity).

downgrade_ssl(TcpSocket, TlsRef, PendingData, Timeout) ->
    do_shutdown_ssl(TcpSocket, TlsRef, ?SSL_SHUTDOWN_BIDIRECTIONAL, PendingData, Timeout).

do_shutdown_ssl(TcpSocket, TlsRef, How, TlsAlertResponseData, Timeout) ->
    case erltls_nif:ssl_shutdown(TlsRef, TlsAlertResponseData) of
        {ok, 1} ->
            ok;
        {ok, Completed, PendingData} ->
            case gen_tcp:send(TcpSocket, PendingData) of
                ok ->
                    case Completed of
                        1 ->
                            ok;
                        _ ->
                            do_shutdown_ssl_continue(TcpSocket, TlsRef, How, Timeout)
                    end;
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

% waits for close alert response if needed. also make sure we read only this
% record and no other tcp traffic that might follow

do_shutdown_ssl_continue(_TcpSocket, _TlsRef, ?SSL_SHUTDOWN_UNIDIRECTIONAL, _Timeout) ->
    ok;
do_shutdown_ssl_continue(TcpSocket, TlsRef, ?SSL_SHUTDOWN_BIDIRECTIONAL, Timeout) ->
    case erltls_nif:ssl_get_method(TlsRef) of
        {ok, Protocol} ->
            RecordHeaderSize = erltls_record:get_protocol_record_header_size(Protocol),
            IsDtls = erltls_record:is_dtls(Protocol),
            case erltls_record:read_next_record(TcpSocket, IsDtls, RecordHeaderSize, Timeout) of
                {ok, Type, Packet} ->
                    case Type of
                        ?SSL_RECORD_ALERT ->
                            do_shutdown_ssl(TcpSocket, TlsRef, ?SSL_SHUTDOWN_BIDIRECTIONAL, Packet, Timeout);
                        _ ->
                            {error, {unexpected_record, Type}}
                    end;
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

close(Pid) ->
    call(Pid, close).

mandatory_cert(?SSL_ROLE_SERVER) ->
    true;
mandatory_cert(?SSL_ROLE_CLIENT) ->
    false.

convert_data(binary, Data) ->
    Data;
convert_data(list, Data) ->
    binary_to_list(Data).