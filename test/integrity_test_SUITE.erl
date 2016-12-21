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
        test_context,
        test_clear_pem_cache,
        test_cipher_suites,
        test_connect_complete,
        test_handshake_failed,
        test_owner_died,
        test_owner_change,
        test_send_recv,
        test_active_mode,
        test_server_mode
    ]}
].

get_certificate() ->
    <<"../../test/server.pem">>.

init_per_suite(Config) ->
    ok = erltls:start(),
    Config.

end_per_suite(_Config) ->
    ok = erltls:stop().

test_context(_Config) ->
    {error, missing_certificate} = erltls_manager:get_ctx(null, null, null, null),
    {ok, Ctx1} = erltls_manager:get_ctx(get_certificate(), null, null, null),
    {ok, Ctx2} = erltls_manager:get_ctx(get_certificate(), null, null, null),
    {ok, _} = erltls_manager:get_ctx(get_certificate(), ["AES128-GCM-SHA256"], null, null),
    Ctx1 =:= Ctx2.

test_clear_pem_cache(_Config) ->
    {ok, Ctx1} = erltls_manager:get_ctx(get_certificate(), ["AES128-GCM-SHA256"], null, null),
    ok = erltls:clear_pem_cache(),
    {ok, Ctx2} = erltls_manager:get_ctx(get_certificate(), ["AES128-GCM-SHA256"], null, null),
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