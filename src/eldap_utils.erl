%%%----------------------------------------------------------------------
%%% File    : eldap_utils.erl
%%% Author  : Mickael Remond <mremond@process-one.net>
%%% Purpose : ejabberd LDAP helper functions
%%% Created : 12 Oct 2006 by Mickael Remond <mremond@process-one.net>
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

-module(eldap_utils).
-author('mremond@process-one.net').

-export([generate_subfilter/1,
	 find_ldap_attrs/2,
	 get_ldap_attr/2,
	 get_user_part/2,
	 make_filter/2,
	 get_state/2,
	 case_insensitive_match/2,
         get_opt/3,
         get_opt/4,
         get_config/1,
         decode_octet_string/3,
	 uids_domain_subst/2,
         get_module_proc/2]).

-include("eldap.hrl").

%% Generate an 'or' LDAP query on one or several attributes
%% If there is only one attribute
generate_subfilter([UID]) ->
    subfilter(UID);
%% If there is several attributes
generate_subfilter(UIDs) ->
    iolist_to_binary(["(|", [subfilter(UID) || UID <- UIDs], ")"]).
%% Subfilter for a single attribute

subfilter({UIDAttr, UIDAttrFormat}) ->
%% The default UiDAttrFormat is %u
    <<$(, UIDAttr/binary, $=, UIDAttrFormat/binary, $)>>;
%% The default UiDAttrFormat is <<"%u">>
subfilter({UIDAttr}) ->
    <<$(, UIDAttr/binary, $=, "%u)">>.

%% Not tail-recursive, but it is not very terribly.
%% It stops finding on the first not empty value.
-spec find_ldap_attrs([{binary()} | {binary(), binary()}],
                      [{binary(), [binary()]}]) -> <<>> | {binary(), binary()}.

find_ldap_attrs([{Attr} | Rest], Attributes) ->
    find_ldap_attrs([{Attr, <<"%u">>} | Rest], Attributes);
find_ldap_attrs([{Attr, Format} | Rest], Attributes) ->
    case get_ldap_attr(Attr, Attributes) of
	Value when is_binary(Value), Value /= <<>> ->
	    {Value, Format};
	_ ->
	    find_ldap_attrs(Rest, Attributes)
    end;
find_ldap_attrs([], _) ->
    <<>>.

-spec get_ldap_attr(binary(), [{binary(), [binary()]}]) -> binary().

get_ldap_attr(LDAPAttr, Attributes) ->
    Res = lists:filter(
	    fun({Name, _}) ->
		    case_insensitive_match(Name, LDAPAttr)
	    end, Attributes),
    case Res of
	[{_, [Value|_]}] -> Value;
	_ -> <<>>
    end.

-spec get_user_part(binary(), binary()) -> {ok, binary()} | {error, badmatch}.

get_user_part(String, Pattern) ->
    F = fun(S, P) ->
		First = str:str(P, <<"%u">>),
		TailLength = byte_size(P) - (First+1),
		str:sub_string(S, First, byte_size(S) - TailLength)
	end,
    case catch F(String, Pattern) of
	{'EXIT', _} ->
	    {error, badmatch};
	Result ->
            case catch ejabberd_regexp:replace(Pattern, <<"%u">>, Result) of
                {'EXIT', _} ->
                    {error, badmatch};
		StringRes ->
                    case case_insensitive_match(StringRes, String) of
                        true ->
                            {ok, Result};
                        false ->
                            {error, badmatch}
                    end
            end
    end.

-spec make_filter([{binary(), [binary()]}], [{binary(), binary()}]) -> any().

make_filter(Data, UIDs) ->
    NewUIDs = [{U, eldap_filter:do_sub(
                     UF, [{<<"%u">>, <<"*%u*">>, 1}])} || {U, UF} <- UIDs],
    Filter = lists:flatmap(
	       fun({Name, [Value | _]}) ->
		       case Name of
			   <<"%u">> when Value /= <<"">> ->
			       case eldap_filter:parse(
				      generate_subfilter(NewUIDs),
                                      [{<<"%u">>, Value}]) of
				   {ok, F} -> [F];
				   _ -> []
			       end;
			   _ when Value /= <<"">> ->
			       [eldap:substrings(
                                  Name,
                                  [{any, Value}])];
			   _ ->
			       []
		       end
	       end, Data),
    case Filter of
	[F] ->
	    F;
	_ ->
	    eldap:'and'(Filter)
    end.

-spec case_insensitive_match(binary(), binary()) -> boolean().

case_insensitive_match(X, Y) ->
    X1 = str:to_lower(X),
    Y1 = str:to_lower(Y),
    if
	X1 == Y1 -> true;
	true -> false
    end.

get_state(Server, Module) ->
    Proc = get_module_proc(Server, Module),
    gen_server:call(Proc, get_state).

%% From the list of uids attribute:
%% we look from alias domain (%d) and make the substitution
%% with the actual host domain
%% This help when you need to configure many virtual domains.
-spec uids_domain_subst(binary(), [{binary(), binary()}]) -> 
                               [{binary(), binary()}].

uids_domain_subst(Name, UIDs) when is_atom(Name)->
    uids_domain_subst(atom_to_binary(Name, latin1), UIDs);

uids_domain_subst(Name, UIDs) ->
    lists:map(fun({U,V}) ->
                      {U, eldap_filter:do_sub(V,[{<<"%d">>, Name}])};
                  (A) -> A 
              end,
              UIDs).


-spec get_opt({atom(), binary()}, list(), fun()) -> any().

get_opt(Name, Key, F) ->
    get_opt(Name, Key, F, undefined).

get_opt(Name, Key, F, Default) ->
    case application:get_env(eldap, Name) of
        undefined -> Default;
        {ok, Opts} ->
            case proplists:get_value(Key, Opts) of
                undefined -> Default;
                Val -> F(Val)
            end
    end.
    

-spec get_config(atom()) -> eldap_config().
get_config(Name) ->
    Servers = get_opt(Name, ldap_servers, 
                      fun(L) ->
                              [iolist_to_binary(H) || H <- L]
                      end, [<<"localhost">>]),
    ?DEBUG("ldap_server ~p",[Servers]),

    Backups = get_opt(Name, ldap_backups, 
                      fun(L) ->
                              [iolist_to_binary(H) || H <- L]
                      end, []),
    ?DEBUG("ldap_backups ~p",[Backups]),

    Encrypt = get_opt(Name, ldap_encrypt,
                      fun(tls) -> tls;
                         (starttls) -> starttls;
                         (none) -> none
                      end, none),
    ?DEBUG("ldap_encrypt ~p",[Encrypt]),

    TLSVerify = get_opt(Name, ldap_tls_verify,
                        fun(hard) -> hard;
                           (soft) -> soft;
                           (false) -> false
                        end, false),
    ?DEBUG("ldap_tls_verify ~p",[TLSVerify]),

    TLSCAFile = get_opt(Name, ldap_tls_cacertfile,
                        fun iolist_to_binary/1),
    ?DEBUG("ldap_tls_cacertfile ~p",[TLSCAFile]),
    
    TLSDepth = get_opt(Name, ldap_tls_depth,
                       fun(I) when is_integer(I), I>=0 -> I end),
    ?DEBUG("ldap_tls_depth ~p",[TLSDepth]),


    Port = get_opt(Name, ldap_port,
                   fun(I) when is_integer(I), I>0 -> I end,
                   case Encrypt of
                       tls -> ?LDAPS_PORT;
                       starttls -> ?LDAP_PORT;
                       _ -> ?LDAP_PORT
                   end),
    ?DEBUG("ldap_port ~p",[Port]),

    RootDN = get_opt(Name, ldap_rootdn, 
                     fun iolist_to_binary/1,
                     <<"">>),
    ?DEBUG("ldap_rootdn ~p",[RootDN]),

    Password = get_opt(Name, ldap_password, 
                 fun iolist_to_binary/1,
                 <<"">>),
    ?DEBUG("ldap_password ~p",[Password]),

    Base = get_opt(Name, ldap_base,
                   fun iolist_to_binary/1,
                   <<"">>),
    ?DEBUG("ldap_base ~p",[Base]),


    OldDerefAliases = get_opt(Name, deref_aliases,
                              fun(never) -> never;
                                 (searching) -> searching;
                                 (finding) -> finding;
                                 (always) -> always
                              end, unspecified),
    ?DEBUG("deref_aliases ~p",[OldDerefAliases]),

    DerefAliases =
        if OldDerefAliases == unspecified ->
                get_opt(Name, ldap_deref_aliases,
                        fun(never) -> never;
                           (searching) -> searching;
                           (finding) -> finding;
                           (always) -> always
                        end, never);
           true ->
                ?WARNING_MSG("Option 'deref_aliases' is deprecated. "
                             "The option is still supported "
                             "but it is better to fix your config: "
                             "use 'ldap_deref_aliases' instead.", []),
                OldDerefAliases
        end,
    ?DEBUG("ldap_deref_aliases ~p",[DerefAliases]),

   #eldap_config{servers = Servers,
                  backups = Backups,
                  tls_options = [{encrypt, Encrypt},
                                 {tls_verify, TLSVerify},
                                 {tls_cacertfile, TLSCAFile},
                                 {tls_depth, TLSDepth}],
                  port = Port,
                  dn = RootDN,
                  password = Password,
                  base = Base,
                  deref_aliases = DerefAliases}.

%%---------------------------------------- 
%% Borrowed from asn1rt_ber_bin_v2.erl
%%----------------------------------------

%%% The tag-number for universal types
-define(N_BOOLEAN, 1). 
-define(N_INTEGER, 2). 
-define(N_BIT_STRING, 3).
-define(N_OCTET_STRING, 4).
-define(N_NULL, 5). 
-define(N_OBJECT_IDENTIFIER, 6). 
-define(N_OBJECT_DESCRIPTOR, 7). 
-define(N_EXTERNAL, 8). 
-define(N_REAL, 9). 
-define(N_ENUMERATED, 10). 
-define(N_EMBEDDED_PDV, 11). 
-define(N_SEQUENCE, 16). 
-define(N_SET, 17). 
-define(N_NumericString, 18).
-define(N_PrintableString, 19).
-define(N_TeletexString, 20).
-define(N_VideotexString, 21).
-define(N_IA5String, 22).
-define(N_UTCTime, 23). 
-define(N_GeneralizedTime, 24). 
-define(N_GraphicString, 25).
-define(N_VisibleString, 26).
-define(N_GeneralString, 27).
-define(N_UniversalString, 28).
-define(N_BMPString, 30).

decode_octet_string(Buffer, Range, Tags) -> 
%    NewTags = new_tags(HasTag,#tag{class=?UNIVERSAL,number=?N_OCTET_STRING}),
    decode_restricted_string(Buffer, Range, Tags).

decode_restricted_string(Tlv, Range, TagsIn) ->
    Val = match_tags(Tlv, TagsIn),
    Val2 = 
	case Val of
	    PartList = [_H|_T] -> % constructed val
		collect_parts(PartList);
	    Bin ->
                Bin
	end,
    check_and_convert_restricted_string(Val2, Range).

check_and_convert_restricted_string(Val, Range) ->
    {StrLen,NewVal} = if is_binary(Val) ->
			      {size(Val), Val};
                         true ->
			      {length(Val), list_to_binary(Val)}
		      end,
    case Range of
	[] -> % No length constraint
	    NewVal;
	{Lb,Ub} when StrLen >= Lb, Ub >= StrLen -> % variable length constraint
	    NewVal;
	{{Lb,_Ub},[]} when StrLen >= Lb ->
	    NewVal;
	{{Lb,_Ub},_Ext=[Min|_]} when StrLen >= Lb; StrLen >= Min ->
	    NewVal;
	{{Lb1,Ub1},{Lb2,Ub2}} when StrLen >= Lb1, StrLen =< Ub1; 
				   StrLen =< Ub2, StrLen >= Lb2 ->
	    NewVal;
	StrLen -> % fixed length constraint
	    NewVal;
	{_,_} -> 
	    exit({error,{asn1,{length,Range,Val}}});
	_Len when is_integer(_Len) ->
	    exit({error,{asn1,{length,Range,Val}}});
	_ -> % some strange constraint that we don't support yet
	    NewVal
    end.

%%---------------------------------------- 
%% Decode the in buffer to bits 
%%---------------------------------------- 
match_tags({T,V},[T]) ->
    V;
match_tags({T,V}, [T|Tt]) ->
    match_tags(V,Tt);
match_tags([{T,V}],[T|Tt]) ->
    match_tags(V, Tt);
match_tags(Vlist = [{T,_V}|_], [T]) ->
    Vlist;
match_tags(Tlv, []) ->
    Tlv;
match_tags({Tag,_V},[T|_Tt]) ->
    {error,{asn1,{wrong_tag,{Tag,T}}}}.

collect_parts(TlvList) ->
    collect_parts(TlvList,[]).

collect_parts([{_,L}|Rest],Acc) when is_list(L) ->
    collect_parts(Rest,[collect_parts(L)|Acc]);
collect_parts([{?N_BIT_STRING,<<Unused,Bits/binary>>}|Rest],_Acc) ->
    collect_parts_bit(Rest,[Bits],Unused);
collect_parts([{_T,V}|Rest],Acc) ->
    collect_parts(Rest,[V|Acc]);
collect_parts([],Acc) ->
    list_to_binary(lists:reverse(Acc)).

collect_parts_bit([{?N_BIT_STRING,<<Unused,Bits/binary>>}|Rest],Acc,Uacc) ->    
    collect_parts_bit(Rest,[Bits|Acc],Unused+Uacc);
collect_parts_bit([],Acc,Uacc) ->
    list_to_binary([Uacc|lists:reverse(Acc)]).


get_module_proc(Name, Base) when is_atom(Name)->
    get_module_proc(erlang:atom_to_binary(Name, latin1), Base);
get_module_proc(Name, Base) ->
    binary_to_atom(
      <<(erlang:atom_to_binary(Base, latin1))/binary, "_", Name/binary>>,
      latin1).
