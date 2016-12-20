-module(erltls_manager).
-author("silviu.caragea").

-behaviour(gen_server).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-export([get_ctx/4, clear_cache/0]).

-define(SERVER, ?MODULE).
-define(ETS_SSL_CONTEXT, etls_ssl_context_table).

-record(state, {}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

get_ctx(KeyFile, Ciphers, DhFile, CaFile) ->
    CtxKey = get_ctx_Key(KeyFile, Ciphers, DhFile, CaFile),
    case ets_get(CtxKey) of
        null ->
            gen_server:call(?MODULE, {get_context, CtxKey, KeyFile, Ciphers, DhFile, CaFile});
        Context ->
            {ok, Context}
    end.

clear_cache() ->
    gen_server:call(?MODULE, clear_cache).

init([]) ->
    ?ETS_SSL_CONTEXT = ets:new(?ETS_SSL_CONTEXT, [set, named_table, protected, {read_concurrency, true}]),
    {ok, #state{}}.

handle_call({get_context, CtxKey, KeyFile, Ciphers, DhFile, CaFile}, _From, State) ->
    Result = case ets_get(CtxKey) of
        null ->
            case erltls_nif:new_context(KeyFile, Ciphers, DhFile, CaFile) of
                {ok, Context} ->
                    true = ets_set(CtxKey, Context),
                    {ok, Context};
                Error ->
                    Error
            end;
        Context ->
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

ets_set(Identifier, Query) ->
    ets:insert(?ETS_SSL_CONTEXT, {Identifier, Query}).

ets_get(Identifier) ->
    case ets:lookup(?ETS_SSL_CONTEXT, Identifier) of
        [{Identifier, Context}] ->
            Context;
        [] ->
            null
    end.

get_ctx_Key(KeyFile, Ciphers, DhFile, CaFile) ->
    KeyFileBin = erltls_utils:to_bin(KeyFile),
    CiphersBin = erltls_utils:to_bin(Ciphers),
    DhFileBin = erltls_utils:to_bin(DhFile),
    CaFileBin = erltls_utils:to_bin(CaFile),
    <<KeyFileBin/binary, "-", CiphersBin/binary, "-", DhFileBin/binary, "-", CaFileBin/binary>>.