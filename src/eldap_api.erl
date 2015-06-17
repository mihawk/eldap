%%%----------------------------------------------------------------------
%%% File    : ejabberd_auth_ldap.erl
%%% Author  : Alexey Shchepin <alexey@process-one.net>
%%% Purpose : Authentification via LDAP
%%% Created : 12 Dec 2004 by Alexey Shchepin <alexey@process-one.net>
%%% 
%%%
%%% ejabberd, Copyright (C) 2002-2015   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License along
%%% with this program; if not, write to the Free Software Foundation, Inc.,
%%% 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
%%%
%%%----------------------------------------------------------------------

-module(eldap_api).

-author('alexey@process-one.net').

-behaviour(gen_server).

%% gen_server callbacks
-export([init/1, handle_info/2, handle_call/3,
	 handle_cast/2, terminate/2, code_change/3]).

%% External exports
-export([
         start/0, 
         start/1,
         stop/1, 
         start_link/1 
        ]).

-export([check_password/3]). 
-export([is_user_exists/2]).
-export([fetch_user/2,
         fetch_user/3]).
-export([get_ufilter/1]).
-export([get_result_attrs/1]).
-export([entries_to_proplist/1]).
-export([print_entry/1]).

-include("eldap.hrl").

-record(state,
	{host = <<"">>          :: binary(),
         eldap_id = <<"">>      :: binary(),
         bind_eldap_id = <<"">> :: binary(),
         servers = []           :: [binary()],
         backups = []           :: [binary()],
         port = ?LDAP_PORT      :: inet:port_number(),
	 tls_options = []       :: list(),
         dn = <<"">>            :: binary(),
         password = <<"">>      :: binary(),
         base = <<"">>          :: binary(),
         uids = []              :: [{binary()} | {binary(), binary()}],
         ufilter = <<"">>       :: binary(),
         sfilter = <<"">>       :: binary(),
	 lfilter                :: {any(), any()},
         deref_aliases = never  :: never | searching | finding | always,
         dn_filter              :: binary(),
         dn_filter_attrs = []   :: [binary()]}).

handle_cast(_Request, State) -> {noreply, State}.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

handle_info(_Info, State) -> {noreply, State}.

-define(LDAP_SEARCH_TIMEOUT, 5).

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------

start() ->
    start(default).
start(Name) ->
    Proc = eldap_utils:get_module_proc(Name, ?MODULE),
    ChildSpec = {Proc, {?MODULE, start_link, [Name]},
		 transient, 1000, worker, [?MODULE]},
    supervisor:start_child(eldap_sup, ChildSpec).

stop(Name) ->
    Proc = eldap_utils:get_module_proc(Name, ?MODULE),
    gen_server:call(Proc, stop),
    supervisor:terminate_child(eldap_sup, Proc),
    supervisor:delete_child(eldap_sup, Proc).

start_link(Name) ->
    Proc = eldap_utils:get_module_proc(Name, ?MODULE),
    gen_server:start_link({local, Proc}, ?MODULE, Name, []).

terminate(_Reason, _State) -> ok.

init(Host) ->
    State = parse_options(Host),
    eldap_pool:start_link(State#state.eldap_id,
			  State#state.servers, State#state.backups,
			  State#state.port, State#state.dn,
			  State#state.password, State#state.tls_options),
    eldap_pool:start_link(State#state.bind_eldap_id,
			  State#state.servers, State#state.backups,
			  State#state.port, State#state.dn,
			  State#state.password, State#state.tls_options),
    {ok, State}.

check_password(Server, User, Password) ->
    if Password == <<"">> -> false;
       true ->
            case catch check_password_ldap(Server, User, Password) of
                {'EXIT', _} -> false;
                Result -> Result
            end
    end.

%% @spec (User, Server) -> true | false | {error, Error}
is_user_exists(Server, User) ->
    case catch is_user_exists_ldap(Server, User) of
      {'EXIT', Error} -> {error, Error};
      Result -> Result
    end.

get_ufilter(Server) ->
    {ok, State} = eldap_utils:get_state(Server, ?MODULE),
    State#state.ufilter.
    
get_result_attrs(Server) ->
    {ok, State} = eldap_utils:get_state(Server, ?MODULE),
    result_attrs(State).

fetch_user(Server, User) ->
    {ok, State} = eldap_utils:get_state(Server, ?MODULE),
    case eldap_filter:parse(State#state.ufilter, [{<<"%u">>, User}]) of
        {ok, Filter} ->
            fetch_user_ldap(State, Filter);
        _ -> {error, filter}
    end.

fetch_user(Server, User, Projection) ->
    {ok, State} = eldap_utils:get_state(Server, ?MODULE),
    case eldap_filter:parse(State#state.ufilter, [{<<"%u">>, User}]) of
        {ok, Filter} ->
            ?DEBUG("Filter ~p",[Filter]),
            fetch_user_ldap(State, Filter, Projection);
        _ -> {error, filter}
    end.

%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------
fetch_user_ldap(State, Filter) ->
    ResAttrs = result_attrs(State),
    fetch_user_ldap(State, Filter, ResAttrs).

fetch_user_ldap(State, Filter, Projection) ->
    case eldap_pool:search(State#state.eldap_id,
                           [
                            {base, State#state.base}
                            ,{filter, Filter}
                            ,{deref_aliases, State#state.deref_aliases}
                            ,{attributes, Projection}
                           ])
    of
        #eldap_search_result{entries = Entries} -> 
            {ok, first_entry_to_proplist(Entries)};
        _ -> []
    end.

    
check_password_ldap(Server, User, Password) ->
    {ok, State} = eldap_utils:get_state(Server, ?MODULE),
    case find_user_dn(User, State) of
      false -> false;
      DN ->
	  case eldap_pool:bind(State#state.bind_eldap_id, DN,
			       Password)
	      of
	    ok -> true;
	    _ -> false
	  end
    end.

is_user_exists_ldap(Server, User) ->
    {ok, State} = eldap_utils:get_state(Server, ?MODULE),
    case find_user_dn(User, State) of
      false -> false;
      _DN -> true
    end.

handle_call(get_state, _From, State) ->
    {reply, {ok, State}, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    {reply, bad_request, State}.

first_entry_to_proplist([]) -> [];
first_entry_to_proplist(Entries) ->
    #eldap_entry{attributes = Attrs, object_name=DN} = hd(Entries),
    [{attributes, Attrs},{object_name, DN}].

entries_to_proplist(Entries) ->
    entries_to_proplist(Entries, []).
entries_to_proplist([], Acc) -> Acc;
entries_to_proplist([#eldap_entry{attributes = Attrs, object_name=DN}|T], Acc) -> 
    entries_to_proplist(T, [[{attributes, Attrs},{object_name, DN}]|Acc]).
        
print_entry([]) -> ok;
print_entry([#eldap_entry{attributes = Attrs, object_name=DN}|T]) -> 
    ?DEBUG(">>> Entrie Attributes ~p",[Attrs]),
    ?DEBUG(">>> Entrie object_name ~p",[DN]),
    print_entry(T).
    
find_user_dn(User, State) ->
    ResAttrs = result_attrs(State),
    case eldap_filter:parse(State#state.ufilter, [{<<"%u">>, User}]) of
      {ok, Filter} ->            
            case eldap_pool:search(State#state.eldap_id,
                                   [{base, State#state.base}, {filter, Filter},
                                    {deref_aliases, State#state.deref_aliases},
                                    {attributes, ResAttrs}])
            of                
                #eldap_search_result{
                   entries=[#eldap_entry{attributes = Attrs, object_name = DN}| _]
                  } -> dn_filter(DN, Attrs, State);
                _ -> false
            end;
        _ -> false
    end.

%% apply the dn filter and the local filter:
dn_filter(DN, Attrs, State) ->
    case check_local_filter(Attrs, State) of
      false -> false;
      true -> is_valid_dn(DN, Attrs, State)
    end.

%% Check that the DN is valid, based on the dn filter
is_valid_dn(DN, _, #state{dn_filter = undefined}) -> DN;
is_valid_dn(DN, Attrs, State) ->
    DNAttrs = State#state.dn_filter_attrs,
    UIDs = State#state.uids,
    Values = [{<<"%s">>,
	       eldap_utils:get_ldap_attr(Attr, Attrs), 1}
	      || Attr <- DNAttrs],
    SubstValues = case eldap_utils:find_ldap_attrs(UIDs,
						   Attrs)
		      of
		    <<"">> -> Values;
		    {S, UAF} ->
			case eldap_utils:get_user_part(S, UAF) of
			  {ok, U} -> [{<<"%u">>, U} | Values];
			  _ -> Values
			end
		  end
		    ++ [{<<"%d">>, State#state.host}, {<<"%D">>, DN}],
    case eldap_filter:parse(State#state.dn_filter,
			    SubstValues)
	of
      {ok, EldapFilter} ->
	  case eldap_pool:search(State#state.eldap_id,
				 [{base, State#state.base},
				  {filter, EldapFilter},
				  {deref_aliases, State#state.deref_aliases},
				  {attributes, [<<"dn">>]}])
	      of
	    #eldap_search_result{entries = [_ | _]} -> DN;
	    _ -> false
	  end;
      _ -> false
    end.

%% The local filter is used to check an attribute in ejabberd
%% and not in LDAP to limit the load on the LDAP directory.
%% A local rule can be either:
%%    {equal, {"accountStatus",["active"]}}
%%    {notequal, {"accountStatus",["disabled"]}}
%% {ldap_local_filter, {notequal, {"accountStatus",["disabled"]}}}
check_local_filter(_Attrs,
		   #state{lfilter = undefined}) ->
    true;
check_local_filter(Attrs,
		   #state{lfilter = LocalFilter}) ->
    {Operation, FilterMatch} = LocalFilter,
    local_filter(Operation, Attrs, FilterMatch).

local_filter(equal, Attrs, FilterMatch) ->
    {Attr, Value} = FilterMatch,
    case lists:keysearch(Attr, 1, Attrs) of
      false -> false;
      {value, {Attr, Value}} -> true;
      _ -> false
    end;
local_filter(notequal, Attrs, FilterMatch) ->
    not local_filter(equal, Attrs, FilterMatch).

result_attrs(#state{uids = UIDs,
		    dn_filter_attrs = DNFilterAttrs}) ->
    lists:foldl(fun ({UID}, Acc) -> [UID | Acc];
		    ({UID, _}, Acc) -> [UID | Acc]
		end,
		DNFilterAttrs, UIDs).

%%%----------------------------------------------------------------------
%%% Auxiliary functions
%%%----------------------------------------------------------------------
parse_options(Name) ->
    Cfg = eldap_utils:get_config(Name),
    Eldap_ID = erlang:atom_to_binary(
                 eldap_utils:get_module_proc(Name, ?MODULE), utf8),
    Bind_Eldap_ID = erlang:atom_to_binary(
                      eldap_utils:get_module_proc(Name, bind_ldap), utf8),
    UIDsTemp = eldap_utils:get_opt(Name, ldap_uids,
                 fun(Us) ->
                         lists:map(
                           fun({U, P}) ->
                                   {iolist_to_binary(U),
                                    iolist_to_binary(P)};
                              ({U}) ->
                                   {iolist_to_binary(U)};
                              (U) ->
                                   {iolist_to_binary(U)}
                           end, lists:flatten(Us))
                 end, [{<<"uid">>, <<"%u">>}]),
    UIDs = eldap_utils:uids_domain_subst(Name, UIDsTemp),
    SubFilter =	eldap_utils:generate_subfilter(UIDs),
    UserFilter = case eldap_utils:get_opt(Name, ldap_filter,
                        fun check_filter/1, <<"">>) of
                     <<"">> ->
			 SubFilter;
                     F ->
                         <<"(&", SubFilter/binary, F/binary, ")">>
                 end,
    SearchFilter = eldap_filter:do_sub(UserFilter,
				       [{<<"%u">>, <<"*">>}]),
    {DNFilter, DNFilterAttrs} =
        eldap_utils:get_opt(Name, ldap_dn_filter,
                    fun([{DNF, DNFA}]) ->
                            NewDNFA = case DNFA of
                                          undefined ->
                                              [];
                                          _ ->
                                              [iolist_to_binary(A)
                                               || A <- DNFA]
                                      end,
                            NewDNF = check_filter(DNF),
                            {NewDNF, NewDNFA}
                    end, {undefined, []}),
    
    LocalFilter = eldap_utils:get_opt(Name, ldap_local_filter, fun(V) -> V end),

    #state{host = atom_to_binary(Name, latin1), 
           eldap_id = Eldap_ID,
           bind_eldap_id = Bind_Eldap_ID,
           servers = Cfg#eldap_config.servers,
	   backups = Cfg#eldap_config.backups,
           port = Cfg#eldap_config.port,
	   tls_options = Cfg#eldap_config.tls_options,
	   dn = Cfg#eldap_config.dn,
           password = Cfg#eldap_config.password,
           base = Cfg#eldap_config.base,
           deref_aliases = Cfg#eldap_config.deref_aliases,
	   uids = UIDs, ufilter = UserFilter,
	   sfilter = SearchFilter, lfilter = LocalFilter,
	   dn_filter = DNFilter, dn_filter_attrs = DNFilterAttrs}.

check_filter(F) ->
    NewF = iolist_to_binary(F),
    {ok, _} = eldap_filter:parse(NewF),
    NewF.


%% -spec nodeprep(binary()) -> binary() | error.

%% nodeprep("") -> <<>>;
%% nodeprep(S) when byte_size(S) < 1024 ->
%%     R = stringprep:nodeprep(S),
%%     if byte_size(R) < 1024 -> R;
%%        true -> error
%%     end;
%% nodeprep(_) -> error.

%% -spec nameprep(binary()) -> binary() | error.

%% nameprep(S) when byte_size(S) < 1024 ->
%%     R = stringprep:nameprep(S),
%%     if byte_size(R) < 1024 -> R;
%%        true -> error
%%     end;
%% nameprep(_) -> error.
