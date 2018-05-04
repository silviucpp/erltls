-module(ranch_erltls).

-behaviour(ranch_transport).

-export([
    name/0,
    secure/0,
    messages/0,
    listen/1,
    accept/2,
    accept_ack/2,
    connect/3,
    connect/4,
    recv/3,
    send/2,
    sendfile/2,
    sendfile/4,
    sendfile/5,
    setopts/2,
    controlling_process/2,
    peername/1,
    sockname/1,
    shutdown/2,
    close/1
]).

-define(DEFAULT_LISTEN_OPTS, [
    {backlog, 1024},
    {nodelay, true},
    {send_timeout, 30000},
    {send_timeout_close, true},
    {reuseaddr, true},
    {mode, binary},
    {active, false},
    {packet, raw}
]).

-define(DEFAULT_CONNECT_OPTS, [
    {mode, binary},
    {active, false},
    {packet, raw}
]).

name() ->
    erltls.

-spec secure() ->
    boolean().

secure() ->
    true.

messages() ->
    {ssl, ssl_closed, ssl_error}.

-spec listen(erltls:listen_option()) ->
    {ok, erltls:tlssocket()} | {error, erltls:reason()}.

listen(Opts0) ->
    case erltls_utils:lookup(port, Opts0) of
        null ->
            {error, no_port};
        Port ->
            Opts = erltls_options:normalize_options(Opts0),
            erltls:listen(Port, apply_default_options(?DEFAULT_LISTEN_OPTS, Opts))
    end.

-spec accept(erltls:tlssocket(), timeout()) ->
    {ok, erltls:tlssocket()} | {error, erltls:reason()}.

accept(LSocket, Timeout) ->
	erltls:transport_accept(LSocket, Timeout).

-spec accept_ack(erltls:tlssocket(), timeout()) ->
    ok  | {error, erltls:reason()}.

accept_ack(CSocket, Timeout) ->
	case erltls:ssl_accept(CSocket, Timeout) of
		ok ->
			ok;
        %garbage data
        {error, invalid_tls_frame} ->
          io:format("Error in accept_ack on Socket ~p: Invalid tls frame, closing and exiting...", [CSocket]),
          ok = close(CSocket),
          exit(normal);
		%% Socket most likely stopped responding, don't error out.
		{error, Reason} when Reason =:= timeout; Reason =:= closed ->
      io:format("Error in accept_ack on Socket ~p: Reason ~p, closing and exiting...~n", [CSocket, Reason]),
			ok = close(CSocket),
			exit(normal);
		{error, Reason} ->
      io:format("Error in accept_ack on Socket ~p: Reason ~p, closing...~n", [CSocket, Reason]),
			ok = close(CSocket),
			error(Reason)
	end.

-spec connect(erltls:host(), inet:port_number(), list()) ->
    {ok, erltls:tlssocket()} | {error, erltls:reason()}.

connect(Host, Port, Opts0) ->
    Opts = erltls_options:normalize_options(Opts0),
	erltls:connect(Host, Port, apply_default_options(?DEFAULT_CONNECT_OPTS, Opts)).

-spec connect(erltls:host(), inet:port_number(), [erltls:connect_option()], timeout()) ->
    {ok, erltls:tlssocket()} | {error, erltls:reason()}.

connect(Host, Port, Options, Timeout) ->
    erltls:connect(Host, Port, Options, Timeout).

-spec recv(erltls:tlssocket(), non_neg_integer(), timeout()) ->
    {ok, binary()| list()} | {error, erltls:reason()}.

recv(Socket, Length, Timeout) ->
	erltls:recv(Socket, Length, Timeout).

-spec send(erltls:tlssocket(), iodata()) ->
    ok | {error, erltls:reason()}.

send(Socket, Packet) ->
	erltls:send(Socket, Packet).

-spec sendfile(erltls:tlssocket(), file:name_all() | file:fd()) ->
    {ok, non_neg_integer()} | {error, term()}.

sendfile(Socket, Filename) ->
	sendfile(Socket, Filename, 0, 0, []).

-spec sendfile(erltls:tlssocket(), file:name_all() | file:fd(), non_neg_integer(), non_neg_integer()) ->
    {ok, non_neg_integer()} | {error, term()}.

sendfile(Socket, File, Offset, Bytes) ->
	sendfile(Socket, File, Offset, Bytes, []).

-spec sendfile(erltls:tlssocket(), file:name_all() | file:fd(), non_neg_integer(), non_neg_integer(), ranch_transport:sendfile_opts()) ->
    {ok, non_neg_integer()} | {error, atom()}.

sendfile(Socket, File, Offset, Bytes, Opts) ->
	ranch_transport:sendfile(?MODULE, Socket, File, Offset, Bytes, Opts).

-spec setopts(erltls:tlssocket(), [gen_tcp:option()]) ->
    ok | {error, erltls:reason()}.

setopts(Socket, Opts) ->
	erltls:setopts(Socket, Opts).

-spec controlling_process(erltls:tlssocket(), pid()) ->
    ok | {error, erltls:reason()}.

controlling_process(Socket, Pid) ->
	erltls:controlling_process(Socket, Pid).

-spec peername(erltls:tlssocket()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, erltls:reason()}.

peername(Socket) ->
	erltls:peername(Socket).

-spec sockname(erltls:tlssocket()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, erltls:reason()}.

sockname(Socket) ->
	erltls:sockname(Socket).

-spec shutdown(erltls:tlssocket(), read | write | read_write) ->
    ok | {error, erltls:reason()}.

shutdown(Socket, How) ->
	erltls:shutdown(Socket, How).

-spec close(erltls:tlssocket()) ->
    term().

close(Socket) ->
	erltls:close(Socket).

% Internal stuffs

apply_default_options([{K, _V} = H|T], Opts) ->
    case lists:keymember(K, 1, Opts) of
        true ->
            apply_default_options(T, Opts);
        false ->
            apply_default_options(T, [H|Opts])
    end;
apply_default_options([], Opts) ->
    Opts.