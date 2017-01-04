-module(integrity_test_SUITE).
-author("silviu.caragea").

-include_lib("common_test/include/ct.hrl").
-include("erltls.hrl").

-compile(export_all).

all() -> [
    {group, erltls_group}
].

groups() -> [
    {erltls_group, [sequence], [
        test_options,
        test_context,
        test_clear_pem_cache,
        test_cipher_suites,
        test_connect_complete,
        test_get_set_opts,
        test_handshake_failed,
        test_owner_died,
        test_owner_change,
        test_send_recv,
        test_active_mode,
        test_list_mode,
        test_server_mode,
        test_session_reused_ticket
    ]}
].

get_certificate() ->
    <<"../../test/server.pem">>.

init_per_suite(Config) ->
    ok = erltls:start(),
    Config.

end_per_suite(_Config) ->
    ok = erltls:stop().

test_options(_Config) ->
    CertFile = "test/server.pem",
    ReuseAddr = true,
    Packet = 0,

    Opts1 = [
        {certfile, CertFile},
        {reuseaddr, ReuseAddr},
        {packet, Packet}
    ],

    {ok, [{reuseaddr, ReuseAddr}], [{certfile, CertFile}], [{packet, Packet}]} = erltls_options:get_options(Opts1),

    {ok, [reuseaddr], [header,packet_size,packet]} = erltls_options:get_inet_names([reuseaddr, packet, packet_size, header]),

    {error,{options,{packet, "ss"}}} = erltls_options:get_options([{packet, "ss"}]),
    {error,{options,{packet_size, "ss"}}} = erltls_options:get_options([{packet_size, "ss"}]),
    {error,{options,{header, "ss"}}} = erltls_options:get_options([{header, "ss"}]),

    {error,{options,{packet, "ss"}}} = erltls_options:get_inet_options([{packet, "ss"}]),
    {error,{options,{packet_size, "ss"}}} = erltls_options:get_inet_options([{packet_size, "ss"}]),
    {error,{options,{header, "ss"}}} = erltls_options:get_inet_options([{header, "ss"}]),

    OptsEmulated = [
        {packet, 1},
        {packet_size, 2},
        {header, 0},
        binary
    ],

    {ok, [], OptsEmulated0} = erltls_options:get_inet_options(OptsEmulated),
    OptsEmulated1 = lists:reverse(OptsEmulated0),

    4 = length(OptsEmulated1),
    1 = erltls_utils:lookup(packet, OptsEmulated1),
    2 = erltls_utils:lookup(packet_size, OptsEmulated1),
    0 = erltls_utils:lookup(header, OptsEmulated1),
    binary = erltls_utils:lookup(mode, OptsEmulated1),

    R1 = erltls_options:emulated_list2record(OptsEmulated1),
    #emulated_opts {packet = 1, packet_size = 2, header = 0, mode = binary} = R1,
    #emulated_opts {packet = 4, packet_size = 2, header = 0, mode = binary} = erltls_options:emulated_list2record([{packet, 4}], R1),
    OptsEmulated1 = erltls_options:emulated_record2list(R1),
    [{packet, 1}] = erltls_options:emulated_by_names([packet], R1),
    true.

test_context(_Config) ->
    {error, missing_certificate} = erltls_manager:get_context([]),
    {ok, Ctx1} = erltls_manager:get_context([{certfile, get_certificate()}]),
    {ok, Ctx2} = erltls_manager:get_context([{certfile, get_certificate()}]),
    {ok, _} = erltls_manager:get_context([{certfile, get_certificate()}, {ciphers, ["AES128-GCM-SHA256"]}]),
    Ctx1 =:= Ctx2.

test_clear_pem_cache(_Config) ->
    {ok, Ctx1} = erltls_manager:get_context([{certfile, get_certificate()}, {ciphers, ["AES128-GCM-SHA256"]}]),
    ok = erltls:clear_pem_cache(),
    {ok, Ctx2} = erltls_manager:get_context([{certfile, get_certificate()}, {ciphers, ["AES128-GCM-SHA256"]}]),
    Ctx1 =/= Ctx2.

test_cipher_suites(_Config) ->
    Ciphers = erltls:cipher_suites(),
    is_list(Ciphers) andalso length(Ciphers) > 0.

test_connect_complete(_Config) ->
    Opt = [
        binary,
        {nodelay, true},
        {packet, 0},
        {active, true},
        {sndbuf, 60000},
        {recbuf, 60000},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none},
        {compression, compression_none}
    ],

    {ok, Socket} = erltls:connect("google.com", 443, Opt),

    true = is_record(Socket, tlssocket),
    {error, _} = erltls:ssl_accept(Socket),
    true = is_process_alive(Socket#tlssocket.ssl_pid),
    ok = erltls:close(Socket),
    false = is_process_alive(Socket#tlssocket.ssl_pid),
    true.

test_get_set_opts(_Config) ->
    DefaultOpts = [
        binary,
        {packet, 0},
        {active, 1},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none},
        {compression, compression_none}
    ],

    {ok, Socket} = erltls:connect("status.github.com", 443, DefaultOpts),
    false = erltls:session_reused(Socket),
    ok = erltls:setopts(Socket, [list, {active, 0}, {packet, 2}]),
    {error,{options,{packet, "ss"}}} = erltls:setopts(Socket, [list, {active, 0}, {packet, "ss"}]),
    {ok, Opts} = erltls:getopts(Socket, [active, packet, packet_size, header]),
    4 = length(Opts),
    1 = erltls_utils:lookup(active, Opts),
    2 = erltls_utils:lookup(packet, Opts),
    0 = erltls_utils:lookup(packet_size, Opts),
    0 = erltls_utils:lookup(header, Opts),
    ok = erltls:close(Socket),
    true.

test_handshake_failed(_Config) ->
    Opt = [
        binary,
        {nodelay, true},
        {packet, 0},
        {active, true},
        {sndbuf, 60000},
        {recbuf, 60000},
        {ciphers, ["DHE-RSA-AES256-SHA"]},
        {verify, verify_none},
        {compression, compression_none}
    ],
    {error, ?SSL_ERROR_SSL} = erltls:connect("google.com", 443, Opt),
    true.

test_owner_died(_Config) ->
    process_flag(trap_exit, true),

    Fun = fun() ->
        Opt = [
            binary,
            {verify, verify_none},
            {compression, compression_none}
        ],

        {ok, Socket} = erltls:connect("google.com", 443, Opt),
        true = is_process_alive(Socket#tlssocket.ssl_pid),
        exit({normal, Socket#tlssocket.ssl_pid})
    end,
    Pid = spawn_link(Fun),

    receive
        {'EXIT',Pid, {normal, SslPid}} ->
            false = is_process_alive(SslPid);
        {'EXIT',Pid, UnexpectedResp} ->
            throw({error, UnexpectedResp})
        after 5000 ->
            throw(timeout)
    end,
    true.

test_owner_change(_Config) ->
    process_flag(trap_exit, true),

    Opt = [
        binary,
        {verify, verify_none},
        {compression, compression_none}
    ],

    {ok, Socket} = erltls:connect("google.com", 443, Opt),

    Fun = fun() ->
        receive
            {owner_set, Sock} ->
                true = is_process_alive(Sock#tlssocket.ssl_pid)
        end
    end,

    Pid = spawn_link(Fun),
    ok = erltls:controlling_process(Socket, Pid),
    Pid ! {owner_set, Socket},

    receive
        {'EXIT',Pid, _} ->
            timer:sleep(1000),
            false = is_process_alive(Socket#tlssocket.ssl_pid)
    after 5000 ->
        throw(timeout)
    end,
    true.

test_send_recv(_Config) ->
    Opt = [
        binary,
        {nodelay, true},
        {packet, 0},
        {active, false},
        {sndbuf, 60000},
        {recbuf, 60000},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none},
        {compression, compression_none}
    ],

    Request = <<"GET /api/status.json?callback=apiStatus HTTP/1.1\r\nHost: status.github.com\r\nCache-Control: no-cache\r\n\r\n">>,

    {ok, Socket} = erltls:connect("status.github.com", 443, Opt),
    ok = erltls:send(Socket, Request),
    case erltls:recv(Socket, 0) of
        {ok, <<"HTTP/", _Rest/binary>>} ->
            true;
        Error ->
            throw(Error)
    end,

    {ok, {_Add, _Port}} = erltls:peername(Socket),
    {ok, {_Add2, _Port2}} = erltls:sockname(Socket),
    {ok, _} = erltls:getstat(Socket),
    {ok, _} = erltls:getstat(Socket, [recv_cnt]),
    ok = erltls:close(Socket),
    true.

test_active_mode(_Config) ->
    Opt = [
        binary,
        {packet, 0},
        {active, 1},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none},
        {compression, compression_none}
    ],

    Request = <<"GET /api/status.json?callback=apiStatus HTTP/1.1\r\nHost: status.github.com\r\nConnection: close\r\n\r\n">>,
    {ok, Socket} = erltls:connect("status.github.com", 443, Opt),
    ok = erltls:send(Socket, Request),

    receive
        {ssl, Socket, <<"HTTP/", _Rest/binary>>} ->
            ok;
        Msg ->
            throw(Msg)
    end,
    ok = erltls:close(Socket),
    true.

test_list_mode(_Config) ->
    Opt = [
        {packet, 0},
        {active, 1},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none},
        {compression, compression_none}
    ],

    Request = <<"GET /api/status.json?callback=apiStatus HTTP/1.1\r\nHost: status.github.com\r\nConnection: close\r\n\r\n">>,
    {ok, Socket} = erltls:connect("status.github.com", 443, Opt),
    ok = erltls:send(Socket, Request),

    receive
        {ssl, Socket, [$H, $T, $T, $P | _Tail]} ->
            ok;
        Msg ->
            throw(Msg)
    end,
    ok = erltls:close(Socket),
    true.

test_server_mode(_Config) ->
    Port = 10000,
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none},
        {compression, compression_none}
    ],

    {ok, LSocket} = erltls:listen(Port, [{certfile, get_certificate()} | Opt]),

    ClientProc = fun() ->
        {ok, CSocket} = erltls:connect("127.0.0.1", Port, Opt),
        ok = erltls:send(CSocket, <<"HELLO">>),
        ok = erltls:setopts(CSocket, [{active, once}]),
        receive
            {ssl, CSocket, <<"HELLO">>} ->
                ok = erltls:close(CSocket);
            Msg ->
                throw(Msg)
        end
    end,

    spawn(ClientProc),

    {ok, Socket} = erltls:transport_accept(LSocket, 5000),
    ok = erltls:ssl_accept(Socket),
    {ok, Data} = erltls:recv(Socket, 0),
    <<"HELLO">> = Data,
    ok = erltls:send(Socket, Data),
    ok = erltls:close(Socket),
    ok = erltls:close(LSocket),
    true.

test_session_reused_ticket(_Config) ->
    spawn(fun()->
        {ok, ListenSocket} = erltls:listen(10001, [
            {certfile, get_certificate()},
            binary,
            {active, false},
            {reuseaddr, true},
            {ciphers, ["AES128-GCM-SHA256"]},
            {verify, verify_none},
            {compression, compression_none},
            {use_session_ticket, {true, <<"ewjfhwejkfhjdhdjkfhdsjfch">>}},
            {reuse_sessions_ttl, 120}
        ]),
        session_reused_server(ListenSocket, 5)
    end),

    true = erltls_ticket_cache:delete_all(),

    ok = resume_client(false),
    ok = resume_client(true),
    ok = resume_client(true),
    ok = resume_client(true),
    ok = resume_client(true),
    true.

session_reused_server(ListenSocket, 0) ->
    erltls:close(ListenSocket);
session_reused_server(ListenSocket, N) ->
    {ok, Socket} = erltls:transport_accept(ListenSocket),
    ok = erltls:setopts(Socket, [{active, false}]),
    ok = erltls:ssl_accept(Socket),
    {ok, <<"foo">>} = erltls:recv(Socket, 0),
    ok = erltls:close(Socket),
    session_reused_server(ListenSocket, N-1).

resume_client(Reused) ->
    {ok, Socket} = erltls:connect("localhost", 10001, [binary, {use_session_ticket, true}, {active, false}], infinity),
    Reused = erltls:session_reused(Socket),
    erltls:send(Socket, "foo").