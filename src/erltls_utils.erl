-module(erltls_utils).

-export([
    to_bin/1,
    lookup/2,
    lookup/3,
    delete/2,
    ets_set/3,
    ets_get/2,
    get_buffer/2
]).

to_bin(Data) when is_binary(Data) ->
    Data;
to_bin(Data) when is_list(Data) ->
    iolist_to_binary(Data);
to_bin(Data) when is_atom(Data) ->
    atom_to_binary(Data, utf8);
to_bin(Data) when is_integer(Data) ->
    integer_to_binary(Data);
to_bin(Data) when is_float(Data) ->
    float_to_binary(Data, [compact, {decimals, 4}]);
to_bin(Data) when is_tuple(Data) ->
    term_to_binary(Data).

lookup(Key, List) ->
    lookup(Key, List, null).

lookup(Key, List, Default) ->
    case lists:keyfind(Key, 1, List) of
        {_, Value} ->
            Value;
        _ ->
            Default
    end.

delete(Key, List) ->
    lists:keydelete(Key, 1, List).

ets_set(Tab, Identifier, Query) ->
    ets:insert(Tab, {Identifier, Query}).

ets_get(Tab, Identifier) ->
    case catch ets:lookup(Tab, Identifier) of
        [{Identifier, Value}] ->
            {ok, Value};
        [] ->
            null;
        Error ->
            Error
    end.

get_buffer(<<>>, NewData) ->
    NewData;
get_buffer(Data, NewData) ->
    <<Data/binary, NewData/binary>>.
