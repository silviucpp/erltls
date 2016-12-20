-module(erltls_utils).
-author("silviu.caragea").

-export([
    to_bin/1,
    lookup/2,
    lookup/3
]).

to_bin(Data) when is_binary(Data) ->
    Data;
to_bin(Data) when is_list(Data) ->
    iolist_to_binary(Data);
to_bin(Data) when is_atom(Data) ->
    atom_to_binary(Data, utf8);
to_bin(Data) when is_integer(Data) ->
    integer_to_binary(Data).

lookup(Key, List) ->
    lookup(Key, List, null).

lookup(Key, List, Default) ->
    case lists:keyfind(Key, 1, List) of
        {_, Value} ->
            Value;
        _ ->
            Default
    end.
