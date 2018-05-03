-module(integrity_test_SUITE).

-include("erltls.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-behaviour(ranch_protocol).

-compile(export_all).

all() -> [
    {group, erltls_group}
].

groups() -> [
    {erltls_group, [sequence], [
        test_options,
        test_context,
        test_context_cert,
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
        test_session_reused_ticket,
        test_peercert,
        test_shutdown,
        downgrade_to_tcp,
        upgrade_to_tls,
        test_dtls_mode,
        test_certificate_keyfile_and_pwd,
        test_cert_key_and_pwd,
        test_cert_and_pwd,
        test_passive_mode,
        test_avoid_getting_empty_packages,
        test_ranch
    ]}
].

get_asn1()->
    <<48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32,76,83,25,118,71,55,80,141,254,233,24,28,216,28,205,37,247,77,
        25,72,10,173,87,215,51,248,24,253,35,105,98,166>>.


get_cert()->
    <<"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
qPLIjcrmQs4AtOIawEM8u86BeoeC">>.

get_cert509()->
    <<48,130,1,16,48,129,195,2,20,0,104,233,220,15,42,133,244,117,51,163,160,1,106,120,61,25,26,173,114,48,5,6,3,43,101,112,48,43,49,41,
        48,39,6,3,85,4,3,12,32,52,55,49,68,52,50,48,51,54,51,53,68,65,67,52,50,68,48,65,55,66,66,66,48,51,55,53,54,54,55,48,56,48,30,23,13,49,56,48,53,48,50,48,48,48,48,48,48,90,23,13,49,57,48,53,48,50,48,48,48,48,48,48,90,48,43,49,41
        ,48,39,6,3,85,4,3,12,32,52,55,49,68,52,50,48,51,54,51,53,68,65,67,52,50,68,48,65,55,66,66,66,48,51,55,53,54,54,55,48,56,48,42,48,5,6,3,43,101,112,3,33,0,97,203,80,156,14,181,1,201,17,25,78,98,79,98,16,98,1,50,97,117,92,0,56,81
        ,143,243,132,89,123,133,111,230,48,5,6,3,43,101,112,3,65,0,116,230,30,240,36,0,164,95,43,201,8,122,242,45,51,196,35,118,91,100,253,104,97,83,197,153,49,128,155,138,204,117,51,112,135,109,108,78,40,205,99,102,86,31,121,177,213,
        234,154,205,90,147,59,19,14,239,232,100,98,176,238,241,83,12>>.

get_priv_key()->
    <<167,215,236,6,150,2,108,52,250,77,216,105,214,133,236,158,45,166,40,70,57,73,34,179,87,162,10,130,204,97,193,190,97,203
        ,80,156,14,181,1,201,17,25,78,98,79,98,16,98,1,50,97,117,92,0,56,81,143,243,132,89,123,133,111,230>>.

get_certificate() ->
    <<"../../test/server.pem">>.

get_certfile() ->
    <<"../../test/certificate.cert">>.

get_keyfile() ->
    <<"../../test/privatekey.key">>.

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

test_context_cert(_Config)->
    {error, missing_certificate} = erltls_manager:get_context([]),
    Cert509 = get_cert(),

    {ok, Ctx1} = erltls_manager:get_context([{cert, Cert509}]),
    {ok, Ctx2} = erltls_manager:get_context([{cert, Cert509}]),

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
        {verify, verify_none}
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
        {verify, verify_none}
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
        {verify, verify_none}
    ],
    {error, _} = erltls:connect("google.com", 443, Opt),
    true.

test_owner_died(_Config) ->
    process_flag(trap_exit, true),

    Fun = fun() ->
        Opt = [
            binary,
            {verify, verify_none}
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
        {active, true}
    ],

    Request = <<"GET /api/status.json?callback=apiStatus HTTP/1.1\r\nHost: status.github.com\r\nConnection: close\r\n\r\n">>,
    {ok, Socket} = erltls:connect("status.github.com", 443, Opt),
    ok = erltls:send(Socket, Request),

    Fun = fun() ->
        receive
            {ssl, Sock, _Data} ->
                true = is_process_alive(Sock#tlssocket.ssl_pid)
        end
    end,

    receive
        {ssl, Socket, Data} ->
            self() ! {ssl, Socket, Data}
    end,

    Pid = spawn_link(Fun),
    ok = erltls:controlling_process(Socket, Pid),

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
        {verify, verify_none}
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
        {verify, verify_none}
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
        {verify, verify_none}
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
        {verify, verify_none}
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

test_peercert(_Config) ->
    {ok, Socket} = erltls:connect("google.com", 443, [], infinity),
    {ok, Cert} = erltls:peercert(Socket),
    true = is_record(public_key:pkix_decode_cert(Cert, plain), 'Certificate'),
    ok = erltls:close(Socket),
    true.


test_shutdown(_Config) ->
    Port = 12000,
    Opt = [
        binary,
        {exit_on_close, false},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    {ok, LSocket} = erltls:listen(Port, [{certfile, get_certificate()} | Opt]),

    ClientProc = fun() ->
        {ok, CSocket} = erltls:connect("127.0.0.1", Port, Opt),
        ok = erltls:send(CSocket, <<"PING">>),
        ok = erltls:shutdown(CSocket, write),
        true = is_process_alive(CSocket#tlssocket.ssl_pid),
        {ok, <<"PONG">> } = erltls:recv(CSocket, 0),
        ok = erltls:close(CSocket),
        false = is_process_alive(CSocket#tlssocket.ssl_pid)
    end,

    spawn(ClientProc),

    {ok, Socket} = erltls:transport_accept(LSocket, 5000),
    ok = erltls:ssl_accept(Socket),

    {ok, <<"PING">> } = erltls:recv(Socket, 0),
    ok = erltls:send(Socket, <<"PONG">>),
    ok = erltls:close(Socket),
    ok = erltls:close(LSocket),
    true.

downgrade_to_tcp(_Config) ->
    Port = 12000,
    Opt = [
        binary,
        {exit_on_close, false},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    {ok, LSocket} = erltls:listen(Port, [{certfile, get_certificate()} | Opt]),

    ClientProc = fun() ->
        {ok, CSocket} = erltls:connect("127.0.0.1", Port, Opt),
        ok = erltls:send(CSocket, <<"PING">>),
        {ok, <<"PONG">> } = erltls:recv(CSocket, 0),

        {ok, TcpSocket} = erltls:close(CSocket, {self(), infinity}),
        {ok, <<"PLAIN_DATA">>} = gen_tcp:recv(TcpSocket, 0),
        ok = gen_tcp:send(TcpSocket, <<"PLAIN_RESPONSE">>),
        ok = gen_tcp:close(TcpSocket)
                 end,

    spawn(ClientProc),

    {ok, Socket} = erltls:transport_accept(LSocket),
    ok = erltls:ssl_accept(Socket),
    {ok, <<"PING">> } = erltls:recv(Socket, 0),
    ok = erltls:send(Socket, <<"PONG">>),
    {ok, TcpSocket} = erltls:close(Socket, {self(), infinity}),

    ok = gen_tcp:send(TcpSocket, <<"PLAIN_DATA">>),
    {ok, <<"PLAIN_RESPONSE">>} = gen_tcp:recv(TcpSocket, 0),
    ok = gen_tcp:close(TcpSocket),
    ok = erltls:close(LSocket),
    true.

upgrade_to_tls(_Config) ->
    Port = 12000,
    InetOpt = [
        binary,
        {exit_on_close, false},
        {active, false}
    ],

    SslOpt = [
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    {ok, LSocket} = gen_tcp:listen(Port, InetOpt),

    ClientProc = fun() ->
        {ok, CSocket} = gen_tcp:connect("127.0.0.1", Port, InetOpt),
        ok = gen_tcp:send(CSocket, <<"PING">>),
        {ok, <<"PONG">> } = gen_tcp:recv(CSocket, 0),

        {ok, TlsSock} = erltls:connect(CSocket, SslOpt),
        ok = erltls:send(TlsSock, <<"PING">>),
        {ok, <<"PONG">> } = erltls:recv(TlsSock, 0),

        ok = erltls:close(TlsSock)
                 end,

    spawn(ClientProc),

    {ok, TcpSocket} = gen_tcp:accept(LSocket),
    {ok, <<"PING">>} = gen_tcp:recv(TcpSocket, 0),
    ok = gen_tcp:send(TcpSocket, <<"PONG">>),

    {ok, SslS_Sock} = erltls:ssl_accept(TcpSocket, [{certfile, get_certificate()} | SslOpt]),
    {ok, <<"PING">> } = erltls:recv(SslS_Sock, 0),
    ok = erltls:send(SslS_Sock, <<"PONG">>),
    ok = erltls:close(SslS_Sock),

    ok = gen_tcp:close(LSocket),
    true.

test_dtls_mode(_Config) ->
    Port = 10000,
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none},
        {protocol, 'dtlsv1.2'}
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

    {ok, L } = erltls:connection_information(Socket),
    'dtlsv1.2' = erltls_utils:lookup(protocol, L),

    {ok, Data} = erltls:recv(Socket, 0),
    <<"HELLO">> = Data,
    ok = erltls:send(Socket, Data),
    ok = erltls:close(Socket),
    ok = erltls:close(LSocket),
    true.

test_certifile_keyfile_and_pwd(_Config) ->
    ServerOpt = [
        {certfile, get_certfile()},
        {keyfile, get_keyfile()},
        {password, "erltls"}
        ],
    do_test_cert_key_and_pwd(ServerOpt).

test_cert_and_pwd(_Config)->
    ServerOpt = [
        {cert, get_cert509()},
        {password, "erltls"}
    ],
    do_test_cert_key_and_pwd(ServerOpt).

test_cert_key_and_pwd(_Config)->
    ServerOpt = [
        {cert, get_cert509()},
        {key, get_priv_key()},
        {password, "erltls"}
    ],
    do_test_cert_key_and_pwd(ServerOpt).

do_test_cert_key_and_pwd(ServerOpt)->

    Port = 10000,
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    {ok, LSocket} = erltls:listen(Port, ServerOpt ++ Opt),

    ClientProc = fun() ->
        {ok, CSocket} = erltls:connect("127.0.0.1", Port, Opt),
        ok = erltls:send(CSocket, <<"PING">>),
        {ok, <<"PONG">>} = erltls:recv(CSocket, 0),
        erltls:close(CSocket)
                 end,

    spawn(ClientProc),

    {ok, Socket} = erltls:transport_accept(LSocket, 5000),
    ok = erltls:ssl_accept(Socket),
    {ok, <<"PING">>} = erltls:recv(Socket, 0),
    ok = erltls:send(Socket, <<"PONG">>),
    ok = erltls:close(Socket),
    ok = erltls:close(LSocket),
    true.

test_passive_mode(_Config) ->
    Port = 10000,
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    Message = <<0:20000/little-signed-integer-unit:8>>,
    MessageSize = byte_size(Message),
    {ok, LSocket} = erltls:listen(Port, [{certfile, get_certificate()} | Opt]),

    ClientProc = fun() ->
        {ok, CSocket} = erltls:connect("127.0.0.1", Port, Opt),
        ok = erltls:send(CSocket, Message)
                 end,

    spawn(ClientProc),

    {ok, Socket} = erltls:transport_accept(LSocket, 5000),
    ok = erltls:ssl_accept(Socket),

    {ok, Message0} = erltls:recv(Socket, MessageSize-4223),
    {ok, Message1} = erltls:recv(Socket, 2021),
    {ok, Message2} = erltls:recv(Socket, 2200),
    Message3 = recv_bytes(Socket, 2, <<>>),
    2 = byte_size(Message3),

    Message = <<Message0/binary, Message1/binary, Message2/binary, Message3/binary>>,
    ok = erltls:close(Socket),
    ok = erltls:close(LSocket),
    true.

test_avoid_getting_empty_packages(_Config) ->
    Port = 10000,
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    Message = <<0:20000/little-signed-integer-unit:8>>,
    {ok, LSocket} = erltls:listen(Port, [{certfile, get_certificate()} | Opt]),

    ClientProc = fun() ->
        {ok, CSocket} = erltls:connect("127.0.0.1", Port, Opt),
        ok = erltls:send(CSocket, Message)
                 end,

    spawn(ClientProc),

    {ok, Socket} = erltls:transport_accept(LSocket, 5000),
    ok = erltls:ssl_accept(Socket),

    Message = recv_bytes(Socket, byte_size(Message), <<>>),

    ok = erltls:close(Socket),
    ok = erltls:close(LSocket),
    true.

recv_bytes(_Socket, 0, Acc) ->
    Acc;
recv_bytes(Socket, Size, Acc) ->
    {ok, [{active, false}]} = erltls:getopts(Socket, [active]),
    ok = erltls:setopts(Socket, [{active, once}]),
    receive
        {ssl, Socket, Message} when byte_size(Message) > 0 ->
            recv_bytes(Socket, Size - byte_size(Message), <<Acc/binary, Message/binary>>);
        Msg ->
            throw(Msg)
    end.


%%%%%%%test ranch %%%%%%%%%

start_link(Ref, Socket, Transport, Opts) ->
    Pid = spawn_link(?MODULE, init, [Ref, Socket, Transport, Opts]),
    {ok, Pid}.

init(Ref, Socket, Transport, _Opts = []) ->
    ok = ranch:accept_ack(Ref),
    loop(Socket, Transport).

loop(Socket, Transport) ->
    case Transport:recv(Socket, 0, 5000) of
        {ok, Data} ->
            Transport:send(Socket, Data),
            loop(Socket, Transport);
        _ ->
            ok = Transport:close(Socket)
    end.

test_ranch(_Config) ->
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    Port = 5555,

    application:ensure_all_started(ranch),
    {ok, _} = ranch:start_listener(integrity_test_SUITE, 1, ranch_erltls, [{port, Port}, {certfile, get_certificate()} | Opt], integrity_test_SUITE, []),

    Data = <<"HELLO WORLD">>,

    {ok, CSocket} = erltls:connect("127.0.0.1", Port, Opt),
    ok = erltls:send(CSocket, Data),
    {ok, Data} = erltls:recv(CSocket, byte_size(Data)),
    ok = erltls:close(CSocket),
    true.