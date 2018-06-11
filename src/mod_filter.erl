%%%----------------------------------------------------------------------
%%% File    : mod_filter.erl
%%% Author  : Magnus Henoch <henoch@dtek.chalmers.se>
%%% Purpose : flexible filtering by server policy
%%% Created : 21 Sep 2005 by Magnus Henoch <henoch@dtek.chalmers.se>
%%% Updated : 14 Jan 2016 by John Brodie <john@brodie.me>
%%%----------------------------------------------------------------------

-module(mod_filter).
-author('henoch@dtek.chalmers.se').
%% -vsn('$Revision$ ').

-behaviour(gen_mod).

-export([start/2, stop/1,
	 filter_packet/1, depends/2, mod_opt_type/1, mod_options/1]).

-include("xmpp.hrl").
-include("ejabberd.hrl").
-include("logger.hrl").

start(_Host, _Opts) ->
    ejabberd_hooks:add(filter_packet, global, ?MODULE, filter_packet, 100).


stop(_Host) ->
    ejabberd_hooks:delete(filter_packet, global, ?MODULE, filter_packet, 100).

%% Return drop to drop the packet, or the original input to let it through.
%% From and To are jid records.
filter_packet(drop) ->
    drop;
filter_packet(Packet) ->
    From = xmpp:get_from(Packet),
    To = xmpp:get_to(Packet),

    %% It probably doesn't make any sense to block packets to oneself.
    Result = if From#jid.luser == To#jid.luser,
		From#jid.lserver == To#jid.lserver ->
		     allow;
		true ->
		     check_stanza(access_rule(Packet), From, To)
	     end,
    lager:debug("filtering packet...~nFrom: ~p~nTo: ~p~nPacket: ~p~nResult: ~p",
		[From, To, Packet, Result]),
    case Result of
	deny -> drop;
	allow -> Packet
    end.

access_rule(#iq{}) ->
    mod_filter_iq;
access_rule(#message{}) ->
    mod_filter_message;
access_rule(#presence{}) ->
    mod_filter_presence.

check_stanza(AccessRule, From, To) ->
    FromAccess = acl:match_rule(global, AccessRule, From),
    case FromAccess of
	allow ->
	    check_access(From, To);
	deny ->
	    deny;
	ToAccessRule ->
	    ToAccess = acl:match_rule(global, ToAccessRule, To),
	    case ToAccess of
		allow ->
		    check_access(From, To);
		deny ->
		    deny
	    end
    end.

check_access(From, To) ->
    %% Beginning of a complicated ACL matching procedure.
    %% The access option given to the module applies to senders.

    %% XXX: there are no "global" module options, and we don't know
    %% anymore what "host" we are on.  Thus hardcoding access rule.
    %%AccessRule = gen_mod:get_module_opt(global, ?MODULE, access, all),
    FromAccess = acl:match_rule(global, ?MODULE, From),
    %% If the rule results in 'allow' or 'deny', treat that as the
    %% result.  Else it is a rule to be applied to the receiver.
    case FromAccess of
	allow ->
	    allow;
	deny ->
	    deny;
	ToAccessRule ->
	    ToAccess = acl:match_rule(global, ToAccessRule, To),
	    case ToAccess of
		allow ->
		    allow;
		deny ->
		    deny
	    end
    end.

depends(_Host, _Opts) ->
    [].

mod_opt_type(access) ->
    fun (A) when is_atom(A) -> A end;

mod_opt_type(_) ->
    [access].

mod_options(_) ->
    [{access, none}].
