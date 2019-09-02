
% records

-record(tlssocket, {
    tcp_sock,
    ssl_pid
}).

-record(emulated_opts, {
    packet =0,
    packet_size = 0,
    header = 0,
    mode = list
}).

% types

-type tls_option()::
    {verify, verify_type()} |
    {depth, integer()} |
    {fail_if_no_peer_cert, boolean()} |
    {certfile, path()} |
    {keyfile, path()} |
    {password, string()} |
    {cacertfile, path()} |
    {dhfile, path()} |
    {ciphers, ciphers()} |
    {protocol, protocol()} |
    {reuse_sessions_ttl, integer()} |
    {use_session_ticket, boolean() | {boolean(), binary()}}.

-type tlssocket()                :: #tlssocket{}.
-type socket_connect_option()    :: gen_tcp:connect_option().
-type socket_listen_option()     :: gen_tcp:listen_option().
-type connect_option()           :: socket_connect_option() | tls_option().
-type listen_option()            :: socket_listen_option() | tls_option().

-type reason()                   :: term().
-type host()		             :: inet:ip_address() | inet:hostname().
-type path()                     :: string().
-type ciphers()                  :: [string()].
-type verify_type()              :: verify_none | verify_peer.
-type protocol()                 :: sslv3 | tlsv1 | 'tlsv1.1' | 'tlsv1.2' | dtlsv1 | 'dtlsv1.2'.

% ssl defines

-define(SSL_ROLE_SERVER, 1).
-define(SSL_ROLE_CLIENT, 2).

-define(SSL_ERROR_WANT_READ, 2).
-define(SSL_ERROR_WANT_WRITE, 3).

-define(SSL_RECORD_CHANGE_CIPHER_SPEC, 20).
-define(SSL_RECORD_ALERT, 21).
-define(SSL_RECORD_HANDSHAKE, 22).
-define(SSL_RECORD_APP_DATA, 23).

% logs

-define(PRINT_MSG(Format, Args),
    io:format("PRINT "++Format++"~n", Args)).

-define(DEBUG_MSG(Format, Args),
    io:format("DEBUG "++Format++"~n", Args)).

-define(INFO_MSG(Format, Args),
    io:format("INFO "++Format++"~n", Args)).

-define(WARNING_MSG(Format, Args),
    io:format("WARNING "++Format++"~n", Args)).

-define(ERROR_MSG(Format, Args),
    io:format("ERROR "++Format++"~n", Args)).

-define(CRITICAL_MSG(Format, Args),
    io:format("CRITICAL "++Format++"~n", Args)).

% others

-define(DEFAULT_TIMEOUT, 5000).
