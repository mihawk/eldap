%%%----------------------------------------------------------------------
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

-define(LDAP_PORT, 389).

-define(LDAPS_PORT, 636).

-type scope() :: baseObject | singleLevel | wholeSubtree.

-record(eldap_search,
	{scope = wholeSubtree              :: scope(),
         base = <<"">>                     :: binary(),
         filter                            :: eldap:filter(),
         limit = 0                         :: non_neg_integer(),
	 attributes = []                   :: [binary()],
         types_only = false                :: boolean(),
	 deref_aliases = neverDerefAliases :: neverDerefAliases |
                                              derefInSearching |
                                              derefFindingBaseObj |
                                              derefAlways,
         timeout = 0                       :: non_neg_integer()}).

-record(eldap_search_result, {entries = []   :: [eldap_entry()],
                              referrals = [] :: list()}).

-record(eldap_entry, {object_name = <<>> :: binary(),
                      attributes = []    :: [{binary(), [binary()]}]}).

-type tlsopts() :: [{encrypt, tls | starttls | none} |
                    {tls_cacertfile, binary() | undefined} |
                    {tls_depth, non_neg_integer() | undefined} |
                    {tls_verify, hard | soft | false}].

-record(eldap_config, {servers = [] :: [binary()],
                       backups = [] :: [binary()],
                       tls_options = [] :: tlsopts(),
                       port = ?LDAP_PORT :: inet:port_number(),
                       dn = <<"">> :: binary(),
                       password = <<"">> :: binary(),
                       base = <<"">> :: binary(),
                       deref_aliases = never :: never | searching |
                                                finding | always}).

-type eldap_config() :: #eldap_config{}.
-type eldap_search() :: #eldap_search{}.
-type eldap_entry() :: #eldap_entry{}.


-compile([{parse_transform, lager_transform}]).

-define(DEBUG(Format, Args),
	lager:debug(Format, Args)).

-define(INFO_MSG(Format, Args),
	lager:info(Format, Args)).

-define(WARNING_MSG(Format, Args),
	lager:warning(Format, Args)).

-define(ERROR_MSG(Format, Args),
	lager:error(Format, Args)).

-define(CRITICAL_MSG(Format, Args),
	lager:critical(Format, Args)).

-ifdef(ERL_DEPRECATED_TYPES).

-define(TDICT, dict()).
-define(TGB_TREE, gb_tree()).
-define(TGB_SET, gb_set()).
-define(TQUEUE, queue()).

-else.

-define(TDICT, dict:dict()).
-define(TGB_TREE, gb_trees:tree()).
-define(TGB_SET, gb_set:set()).
-define(TQUEUE, queue:queue()).

-endif.
