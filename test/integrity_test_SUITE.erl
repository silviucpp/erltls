-module(integrity_test_SUITE).

-include("erltls.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-behaviour(ranch_protocol).

-compile(export_all).

all() -> [
  {group, erltls_group_file},
  {group, erltls_group_asn1}
].

groups() -> [
    {erltls_group_file, [sequence], [
        test_options,
        %% cerfile and keyfile tests
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
        test_session_reused_ticket,
        test_peercert,
        test_shutdown,
        downgrade_to_tcp,
        upgrade_to_tls_certfile,
        test_dtls_mode,
        test_certfile_keyfile_and_pwd,
        test_passive_mode,
        test_avoid_getting_empty_packages,
        test_ranch
    ]},
  {erltls_group_asn1, [sequence], [
    %% cert and key ASN1 tests
    test_context_cert_and_key,
    upgrade_to_tls_cert_and_key,
    test_cert_key_and_pwd
  ]}
].

get_priv_key_asn1()->
  <<48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32,180,229,174,250,111,134,17,1,10,239,143,28,123,121,29,138,25,9,9,220,
    109,67,34,144,86,38,73,88,126,38,126,107>>.

get_cert509_asn1()->
    <<48,130,1,16,48,129,195,2,20,0,74,187,70,248,92,212,238,210,128,226,186,193,43,36,76,251,177,101,
      123,48,5,6,3,43,101,112,48,43,49,41,48,39,6,3,85,4,3,12,32,54,49,57,48,65,69,51,53,54,48,53,54,51,66,54,69,66,
      56,55,48,55,48,52,53,57,54,56,56,68,66,69,68,48,30,23,13,49,56,48,53,48,51,48,48,48,48,48,48,90,23,13,49,57,48,
      53,48,51,48,48,48,48,48,48,90,48,43,49,41,48,39,6,3,85,4,3,12,32,54,49,57,48,65,69,51,53,54,48,53,54,51,66,54,
      69,66,56,55,48,55,48,52,53,57,54,56,56,68,66,69,68,48,42,48,5,6,3,43,101,112,3,33,0,68,200,153,59,156,124,
      69,239,131,53,253,11,174,197,37,116,231,222,102,197,240,83,83,209,29,110,212,185,125,112,136,108,48,5,6,3,43,101,
      112,3,65,0,7,33,146,201,205,110,89,30,184,169,20,183,167,253,179,24,251,187,5,251,29,101,163,81,12,94,175,39,81,
      214,104,65,75,106,144,184,10,10,165,196,234,199,159,39,172,79,246,95,188,55,146,84,179,28,17,59,147,236,85,
      115,8,231,103,0>>.

get_certificate(DataDir) -> filename:join(DataDir, "server.pem").

get_certfile(DataDir) -> filename:join(DataDir, "certificate.cert").

get_keyfile(DataDir) -> filename:join(DataDir, "privatekey.key").

init_per_suite(Config) ->
    application:ensure_all_started(lager),
    ok = erltls:start(),
    Config.

end_per_suite(_Config) ->
    ok = erltls:stop().

test_options(Config) ->
    DataDir = ?config(data_dir, Config),

    CertFile = filename:join(DataDir, get_certfile(DataDir)),
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

test_context(Config) ->
    DataDir = ?config(data_dir, Config),
    {error, missing_certificate} = erltls_manager:get_context([]),
    CertFile = get_certificate(DataDir),
    {ok, Ctx1} = erltls_manager:get_context([{certfile, CertFile}]),
    {ok, Ctx2} = erltls_manager:get_context([{certfile, CertFile}]),
    {ok, _} = erltls_manager:get_context([{certfile, CertFile}, {ciphers, ["AES128-GCM-SHA256"]}]),
    Ctx1 =:= Ctx2.

test_context_cert_and_key(_Config)->
    {error, missing_certificate} = erltls_manager:get_context([]),
    Cert509 = get_cert509_asn1(),
    PrivKey = get_priv_key_asn1(),

    {ok, Ctx1} = erltls_manager:get_context([{cert, Cert509}, {key, PrivKey}]),
    {ok, Ctx2} = erltls_manager:get_context([{cert, Cert509}, {key, PrivKey}]),

    Ctx1 =:= Ctx2.


test_clear_pem_cache(Config) ->
    DataDir = ?config(data_dir, Config),
    CertFile = get_certificate(DataDir),
    {ok, Ctx1} = erltls_manager:get_context([{certfile, CertFile}, {ciphers, ["AES128-GCM-SHA256"]}]),
    ok = erltls:clear_pem_cache(),
    {ok, Ctx2} = erltls_manager:get_context([{certfile, CertFile}, {ciphers, ["AES128-GCM-SHA256"]}]),
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

test_server_mode(Config) ->
    DataDir = ?config(data_dir, Config),
    CertFile = get_certificate(DataDir),

    Port = 10000,
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    {ok, LSocket} = erltls:listen(Port, [{certfile, CertFile} | Opt]),

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

test_session_reused_ticket(Config) ->
  DataDir = ?config(data_dir, Config),
  CertFile = get_certificate(DataDir),
    spawn(fun()->
        {ok, ListenSocket} = erltls:listen(10001, [
            {certfile, CertFile},
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


test_shutdown(Config) ->
  DataDir = ?config(data_dir, Config),
  CertFile = get_certificate(DataDir),
    Port = 12000,
    Opt = [
        binary,
        {exit_on_close, false},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    {ok, LSocket} = erltls:listen(Port, [{certfile, CertFile} | Opt]),

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

downgrade_to_tcp(Config) ->
  DataDir = ?config(data_dir, Config),
  CertFile = get_certificate(DataDir),
    Port = 12000,
    Opt = [
        binary,
        {exit_on_close, false},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    {ok, LSocket} = erltls:listen(Port, [{certfile, CertFile} | Opt]),

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

upgrade_to_tls_certfile(Config)->
  DataDir = ?config(data_dir, Config),
  CertFile = get_certificate(DataDir),
  do_upgrade_to_tls(Config, [{certfile, CertFile}], 12000).

upgrade_to_tls_cert_and_key(Config)->
  do_upgrade_to_tls(Config, [{cert, get_cert509_asn1()}, {key, get_priv_key_asn1()}], 12001).

do_upgrade_to_tls(_Config, CertOpt, Port) ->
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

    {ok, SslS_Sock} = erltls:ssl_accept(TcpSocket, CertOpt ++ SslOpt),
    {ok, <<"PING">> } = erltls:recv(SslS_Sock, 0),
    ok = erltls:send(SslS_Sock, <<"PONG">>),
    ok = erltls:close(SslS_Sock),

    ok = gen_tcp:close(LSocket),
    true.

test_dtls_mode(Config) ->
  DataDir = ?config(data_dir, Config),
  CertFile = get_certificate(DataDir),
    Port = 10000,
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none},
        {protocol, 'dtlsv1.2'}
    ],

    {ok, LSocket} = erltls:listen(Port, [{certfile, CertFile} | Opt]),

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

test_certfile_keyfile_and_pwd(Config) ->
   DataDir = ?config(data_dir, Config),
    ServerOpt = [
        {certfile, get_certfile(DataDir)},
        {keyfile, get_keyfile(DataDir)},
        {password, "erltls"}
        ],
    do_test_cert_key_and_pwd(ServerOpt, 10000).

test_cert_key_and_pwd(_Config)->
    ServerOpt = [
        {cert, get_cert509_asn1()},
        {key, get_priv_key_asn1()},
        {password, "erltls"}
    ],
    do_test_cert_key_and_pwd(ServerOpt, 10001).

do_test_cert_key_and_pwd(ServerOpt, Port)->

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

test_passive_mode(Config) ->
  DataDir = ?config(data_dir, Config),
  CertFile = get_certificate(DataDir),
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
    {ok, LSocket} = erltls:listen(Port, [{certfile, CertFile} | Opt]),

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

test_avoid_getting_empty_packages(Config) ->
  DataDir = ?config(data_dir, Config),
  CertFile = get_certificate(DataDir),
    Port = 10000,
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    Message = <<0:20000/little-signed-integer-unit:8>>,
    {ok, LSocket} = erltls:listen(Port, [{certfile, CertFile} | Opt]),

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

test_ranch(Config) ->
  DataDir = ?config(data_dir, Config),
  CertFile = get_certificate(DataDir),
    Opt = [
        binary,
        {packet, 0},
        {active, false},
        {ciphers, ["AES128-GCM-SHA256"]},
        {verify, verify_none}
    ],

    Port = 5555,

    application:ensure_all_started(ranch),
    {ok, _} = ranch:start_listener(integrity_test_SUITE, 1, ranch_erltls, [{port, Port}, {certfile, CertFile} | Opt], integrity_test_SUITE, []),

    Data = <<"HELLO WORLD">>,

    {ok, CSocket} = erltls:connect("127.0.0.1", Port, Opt),
    ok = erltls:send(CSocket, Data),
    {ok, Data} = erltls:recv(CSocket, byte_size(Data)),
    ok = erltls:close(CSocket),
    true.