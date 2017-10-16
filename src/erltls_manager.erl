-module(erltls_manager).

-behaviour(gen_server).

-export([
    start_link/0,
    get_context/1,
    get_context/2,
    clear_cache/0,

    % gen_server

    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(SERVER, ?MODULE).
-define(ETS_SSL_CONTEXT, etls_ssl_context_table).
-define(DEFAULT_CIPHERS, <<"DEFAULT:!EXPORT:!LOW:!RC4:!SSLv2">>).

-record(state, {}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

get_context(TlsOpts) ->
    get_context(TlsOpts, true).

get_context(TlsOptions, MandatoryCertificate) ->
    CertFile = erltls_utils:lookup(certfile, TlsOptions),

    case missing_cert(CertFile, MandatoryCertificate) of
        true ->
            {error, missing_certificate};
        _ ->
            ContextHash = get_context_hash(TlsOptions),
            case erltls_utils:ets_get(?ETS_SSL_CONTEXT, ContextHash) of
                null ->
                    gen_server:call(?MODULE, {get_context, ContextHash, TlsOptions});
                {ok, Context} ->
                    {ok, Context}
            end
    end.

clear_cache() ->
    gen_server:call(?MODULE, clear_cache).

init([]) ->
    ?ETS_SSL_CONTEXT = ets:new(?ETS_SSL_CONTEXT, [set, named_table, protected, {read_concurrency, true}]),
    {ok, #state{}}.

handle_call({get_context, ContextHash, TlsOptions0}, _From, State) ->
    Result = case erltls_utils:ets_get(?ETS_SSL_CONTEXT, ContextHash) of
        null ->
            Ciphers = get_ciphers(erltls_utils:lookup(ciphers, TlsOptions0)),
            TlsOptions = [{ciphers, Ciphers} | erltls_utils:delete(ciphers, TlsOptions0)],

            case erltls_nif:new_context(TlsOptions) of
                {ok, Context} ->
                    true = erltls_utils:ets_set(?ETS_SSL_CONTEXT, ContextHash, Context),
                    {ok, Context};
                Error ->
                    Error
            end;
        {ok, Context} ->
            {ok, Context}
    end,
    {reply, Result, State};

handle_call(clear_cache, _From, State) ->
    Rs = ets:delete_all_objects(?ETS_SSL_CONTEXT),
    {reply, Rs, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%internals

get_context_hash([]) ->
    <<"default">>;
get_context_hash(Options) ->
    ValuesBin = lists:foldl(fun({_K, V}, Acc) -> [erltls_utils:to_bin(V) | Acc] end, [], lists:keysort(1, Options)),
    crypto:hash(sha, ValuesBin).

missing_cert(_, false) ->
    false;
missing_cert(Cert, true) when is_list(Cert) ->
    length(Cert) =:= 0;
missing_cert(Cert, true) when is_binary(Cert) ->
    byte_size(Cert) =:= 0;
missing_cert(_, true) ->
    true.

get_ciphers(null) ->
    ?DEFAULT_CIPHERS;
get_ciphers(Ciphers) when is_list(Ciphers) ->
    string:join(Ciphers, ":").