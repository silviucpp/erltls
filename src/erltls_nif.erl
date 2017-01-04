-module(erltls_nif).
-author("silviu.caragea").

-define(NOT_LOADED, not_loaded(?LINE)).

-on_load(load_nif/0).

-export([
    new_context/1,
    ciphers/1,
    ssl_new/4,
    ssl_handshake/1,
    ssl_send_pending/1,
    ssl_feed_data/2,
    ssl_send_data/2,
    ssl_shutdown/1,
    ssl_session_reused/1,
    ssl_get_session_asn1/1,
    ssl_peercert/1
]).

%% nif functions

load_nif() ->
    SoName = get_nif_library_path(),
    io:format(<<"Loading library: ~p ~n">>, [SoName]),
    ok = erlang:load_nif(SoName, 0).

get_nif_library_path() ->
    case code:priv_dir(erltls) of
        {error, bad_name} ->
            case filelib:is_dir(filename:join(["..", priv])) of
                true ->
                    filename:join(["..", priv, ?MODULE]);
                false ->
                    filename:join([priv, ?MODULE])
            end;
        Dir ->
            filename:join(Dir, ?MODULE)
    end.

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

new_context(_TlsOptions) ->
    ?NOT_LOADED.

ciphers(_Ctx) ->
    ?NOT_LOADED.

ssl_new(_Context, _Role, _Flags, _CachedSession) ->
    ?NOT_LOADED.

ssl_handshake(_SocketRef) ->
    ?NOT_LOADED.

ssl_send_pending(_SocketRef) ->
    ?NOT_LOADED.

ssl_feed_data(_SocketRef, _Bin) ->
    ?NOT_LOADED.

ssl_send_data(_SocketRef, _Bin) ->
    ?NOT_LOADED.

ssl_shutdown(_SocketRef) ->
    ?NOT_LOADED.

ssl_session_reused(_SocketRef) ->
    ?NOT_LOADED.

ssl_get_session_asn1(_SocketRef) ->
    ?NOT_LOADED.

ssl_peercert(_SocketRef) ->
    ?NOT_LOADED.
