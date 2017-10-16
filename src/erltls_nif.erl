-module(erltls_nif).

-define(NOT_LOADED, not_loaded(?LINE)).
%% Maximum bytes passed to the NIF handler at once (40Kb)
-define(MAX_BYTES_TO_NIF, 40960).

-on_load(load_nif/0).

-export([
    new_context/1,
    ciphers/1,
    ssl_new/4,
    ssl_set_owner/2,
    ssl_handshake/1,
    ssl_send_pending/1,
    chunk_send_data/2,
    chunk_feed_data/2,
    ssl_feed_data/2,
    ssl_send_data/2,
    ssl_shutdown/2,
    ssl_session_reused/1,
    ssl_get_session_asn1/1,
    ssl_peercert/1,
    ssl_get_method/1,
    ssl_get_session_info/1,
    version/0
]).

%% nif functions

load_nif() ->
    SoName = get_priv_path(?MODULE),
    io:format(<<"Loading library: ~p ~n">>, [SoName]),
    ok = erlang:load_nif(SoName, 0).

get_priv_path(File) ->
    case code:priv_dir(erltls) of
        {error, bad_name} ->
            Ebin = filename:dirname(code:which(?MODULE)),
            filename:join([filename:dirname(Ebin), "priv", File]);
        Dir ->
            filename:join(Dir, File)
    end.

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

new_context(_TlsOptions) ->
    ?NOT_LOADED.

ciphers(_Ctx) ->
    ?NOT_LOADED.

ssl_new(_Context, _Role, _Flags, _CachedSession) ->
    ?NOT_LOADED.

ssl_set_owner(_SocketRef, _Pid) ->
    ?NOT_LOADED.

ssl_handshake(_SocketRef) ->
    ?NOT_LOADED.

ssl_send_pending(_SocketRef) ->
    ?NOT_LOADED.

ssl_feed_data(_SocketRef, _Bin) ->
    ?NOT_LOADED.

ssl_send_data(_SocketRef, _Bin) ->
    ?NOT_LOADED.

ssl_shutdown(_SocketRef, _Buff) ->
    ?NOT_LOADED.

ssl_session_reused(_SocketRef) ->
    ?NOT_LOADED.

ssl_get_session_asn1(_SocketRef) ->
    ?NOT_LOADED.

ssl_peercert(_SocketRef) ->
    ?NOT_LOADED.

ssl_get_method(_SocketRef) ->
    ?NOT_LOADED.

ssl_get_session_info(_SocketRef) ->
    ?NOT_LOADED.

version() ->
    ?NOT_LOADED.

chunk_send_data(TlsSock, Data) when is_binary(Data) ->
    chunk_send_data(TlsSock, Data, byte_size(Data), <<>>);
chunk_send_data(TlsSock, Data) ->
    chunk_send_data(TlsSock, iolist_to_binary(Data)).

chunk_send_data(TlsSock, Data, Size, Buffer) ->
    case Size > ?MAX_BYTES_TO_NIF of
        true ->
            <<Chunk:?MAX_BYTES_TO_NIF/binary, Rest/binary>> = Data,
            case ssl_send_data(TlsSock, Chunk) of
                {ok, ProcessedData} ->
                    chunk_send_data(TlsSock, Rest, Size - ?MAX_BYTES_TO_NIF, erltls_utils:get_buffer(Buffer, ProcessedData));
                Error ->
                    Error
            end;
        _ ->
            case ssl_send_data(TlsSock, Data) of
                {ok, ProcessedData} ->
                    {ok, erltls_utils:get_buffer(Buffer, ProcessedData)};
                Error ->
                    Error
            end
    end.

chunk_feed_data(TlsSock, Data) ->
    chunk_feed_data(TlsSock, Data, byte_size(Data), <<>>).

chunk_feed_data(TlsSock, Data, Size, Buffer) ->
    case Size > ?MAX_BYTES_TO_NIF of
        true ->
            <<Chunk:?MAX_BYTES_TO_NIF/binary, Rest/binary>> = Data,
            case ssl_feed_data(TlsSock, Chunk) of
                {ok, ProcessedData} ->
                    chunk_feed_data(TlsSock, Rest, Size - ?MAX_BYTES_TO_NIF, erltls_utils:get_buffer(Buffer, ProcessedData));
                Error ->
                    Error
            end;
        _ ->
            case ssl_feed_data(TlsSock, Data) of
                {ok, ProcessedData} ->
                    {ok, erltls_utils:get_buffer(Buffer, ProcessedData)};
                Error ->
                    Error
            end
    end.