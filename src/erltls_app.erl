-module(erltls_app).

-behaviour(application).

-export([
    start/2,
    stop/1
]).

start(_StartType, _StartArgs) ->
    ok = erltls_ticket_cache:init(),
    erltls_sup:start_link().

stop(_State) ->
    ok.
