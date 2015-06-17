-module(eldap_app).
-behaviour(application).

-include("eldap.hrl").

-export([start/2]).
-export([stop/1]).

-spec start(_, _) -> {ok, pid()}.
start(_, _) ->
    eldap_sup:start_link().

-spec stop(_) -> ok.
stop(_) ->
	ok.
