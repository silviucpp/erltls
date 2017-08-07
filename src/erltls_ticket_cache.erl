-module(erltls_ticket_cache).

-define(ETS_TICKET_CACHE, etls_ticket_cache_table).
-define(GET_KEY(Host, Port), {Host, Port}).

-export([
    init/0,
    get/2,
    set/3,
    delete_all/0
]).

init() ->
    ?ETS_TICKET_CACHE = ets:new(?ETS_TICKET_CACHE, [set, named_table, public, {read_concurrency, true}]),
    ok.

get(Host, Port) ->
    erltls_utils:ets_get(?ETS_TICKET_CACHE, ?GET_KEY(Host, Port)).

set(Host, Port, SessionASN1) ->
    erltls_utils:ets_set(?ETS_TICKET_CACHE, ?GET_KEY(Host, Port), SessionASN1).

delete_all() ->
    ets:delete_all_objects(?ETS_TICKET_CACHE).
