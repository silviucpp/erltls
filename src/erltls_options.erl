-module(erltls_options).
-author("silviu.caragea").

-include("erltls.hrl").

-export([
    get_inet_names/1,
    get_inet_options/1,
    get_options/1,
    default_emulated/0,
    emulated_list2record/1,
    emulated_list2record/2,
    emulated_record2list/1,
    emulated_by_names/2
]).

get_inet_names(Opt) ->
    get_inet_names(Opt, [], []).

get_inet_names([H|T], InetNames, EmulatedNames) ->
    case is_emulated_option(H) of
        true ->
            get_inet_names(T, InetNames, [H|EmulatedNames]);
        _ ->
            get_inet_names(T, [H|InetNames], EmulatedNames)
    end;
get_inet_names([], InetNames, EmulatedNames) ->
    {ok, InetNames, EmulatedNames}.

get_inet_options(Opt) ->
    try
        get_inet_options(Opt, [], [])
    catch
        _:Error ->
            Error
    end.

get_inet_options([H|T], TcpOpt, EmulatedOpt) ->
    OptionKey = get_option_key(H),

    case is_emulated_option(OptionKey) of
        true ->
            {K, V} = H,
            validate_emulated_option(K, V),
            get_inet_options(T, TcpOpt, [H|EmulatedOpt]);
        _ ->
            get_inet_options(T, [H|TcpOpt], EmulatedOpt)
    end;
get_inet_options([], TcpOpt, EmulatedOpt) ->
    {ok, TcpOpt, EmulatedOpt}.

get_options(Options) ->
    try
        get_options(Options, [], [], [])
    catch
        _:Error ->
            Error
    end.

get_options([H|T], TcpOpt, TlsOpt, EmulatedOpt) ->
    OptionKey = get_option_key(H),

    case is_tls_option(OptionKey) of
        true ->
            get_options(T, TcpOpt, [H|TlsOpt], EmulatedOpt);
        _ ->
            case is_emulated_option(OptionKey) of
                false ->
                    get_options(T, [H|TcpOpt], TlsOpt, EmulatedOpt);
                _ ->
                    {K, V} = H,
                    validate_emulated_option(K, V),
                    get_options(T, TcpOpt, TlsOpt, [H|EmulatedOpt])
            end
    end;
get_options([], TcpOpt, TlsOpt, EmulatedOpt) ->
    {ok, TcpOpt, TlsOpt, EmulatedOpt}.

get_option_key(El) when is_tuple(El) ->
    element(1, El);
get_option_key(Key) when is_atom(Key) ->
    Key.

is_tls_option(Key) ->
    lists:member(Key, [
        certfile, dhfile, cacerts, ciphers, verify, compression,
        % not implemented.
        % todo: implement the following methods
        verify_fun, fail_if_no_peer_cert, depts, cert, key, keyfile, password,
        cacertfile, dh, user_lookup_fun, psk_identity, srp_identity, ssl_imp,
        hibernate_after, reuse_sessions, reuse_session, alpn_advertised_protocols,
        alpn_preferred_protocols, next_protocols_advertised, client_preferred_next_protocols,
        log_alert, server_name_indication, sni_hosts, sni_fun
    ]).

is_emulated_option(header) ->
    true;
is_emulated_option(packet) ->
    true;
is_emulated_option(packet_size) ->
    true;
is_emulated_option(_) ->
    false.

validate_emulated_option(packet, Value) when not (is_atom(Value) orelse is_integer(Value)) ->
    throw({error, {options, {packet,Value}}});
validate_emulated_option(packet_size, Value) when not is_integer(Value) ->
    throw({error, {options, {packet_size,Value}}});
validate_emulated_option(header, Value) when not is_integer(Value) ->
    throw({error, {options, {header,Value}}});
validate_emulated_option(_, _) ->
    ok.

default_emulated() -> [
    {packet, 0},
    {packet_size, 0},
    {header, 0}
].

emulated_list2record(OptionsList) ->
    emulated_list2record(OptionsList, #emulated_opts{}).

emulated_list2record([{K, V} | T], Rc) ->
    case K of
        packet ->
            emulated_list2record(T, Rc#emulated_opts{packet = V});
        packet_size ->
            emulated_list2record(T, Rc#emulated_opts{packet_size = V});
        header ->
            emulated_list2record(T, Rc#emulated_opts{header = V})
    end;
emulated_list2record([], Rc) ->
    Rc.

emulated_record2list(#emulated_opts{packet = Packet, packet_size = PkSize, header = Header}) -> [
    {packet, Packet},
    {packet_size, PkSize},
    {header, Header}
].

emulated_by_names(Names, Emul) ->
    emulated_by_names(Names, Emul, []).

emulated_by_names([H|T], Emul, Acc) ->
    case H of
        packet ->
            emulated_by_names(T, Emul, [{packet, Emul#emulated_opts.packet} | Acc]);
        packet_size ->
            emulated_by_names(T, Emul, [{packet_size, Emul#emulated_opts.packet_size} | Acc]);
        header ->
            emulated_by_names(T, Emul, [{header, Emul#emulated_opts.header} | Acc])
    end;
emulated_by_names([], _Emul, Acc) ->
    Acc.
