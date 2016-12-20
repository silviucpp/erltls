-author("silviu.caragea").

%socket ref

-record(tlssocket, {tcp_sock, ssl_pid, tls_opt = undefined}).

%ssl stuffs

-define(SSL_ROLE_SERVER, 1).
-define(SSL_ROLE_CLIENT, 2).

-define(SSL_ERROR_SSL, 1).
-define(SSL_ERROR_WANT_READ, 2).
-define(SSL_ERROR_WANT_WRITE, 3).

%logs

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