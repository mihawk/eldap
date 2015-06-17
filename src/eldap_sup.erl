-module(eldap_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-spec start_link() -> {ok, pid()}.
start_link() ->
	supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec init([])
	-> {ok, {{supervisor:strategy(), 10, 10}, [supervisor:child_spec()]}}.
init([]) ->
    Procs = [],
    {ok, {{one_for_one, 10, 10}, Procs}}.

