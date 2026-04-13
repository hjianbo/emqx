%%--------------------------------------------------------------------
%% Copyright (c) 2018-2025 EMQ Technologies Co., Ltd. All Rights Reserved.
%%--------------------------------------------------------------------

-module(emqx_quick_priority).

-include("emqx_mqtt.hrl").

-export([prioritize_incoming_packets/1]).

-define(PT_QUICK_UPLINK_TOPIC_MATCH_MFA, {emqx_whc_hacker, quick_uplink_topic_match_mfa}).

-spec prioritize_incoming_packets([term()]) -> [term()].
prioritize_incoming_packets(Packets) when is_list(Packets) ->
    {QuickPackets, NormalPackets} = lists:partition(
        fun is_quick_uplink_publish_packet/1,
        Packets
    ),
    QuickPackets ++ NormalPackets.

is_quick_uplink_publish_packet(#mqtt_packet{variable = #mqtt_packet_publish{topic_name = Topic}}) ->
    is_quick_uplink_topic(Topic);
is_quick_uplink_publish_packet(_) ->
    false.

is_quick_uplink_topic(Topic) when is_binary(Topic) ->
    do_is_quick_uplink_topic(
        Topic, persistent_term:get(?PT_QUICK_UPLINK_TOPIC_MATCH_MFA, undefined)
    );
is_quick_uplink_topic(_) ->
    false.

do_is_quick_uplink_topic(Topic, {Module, Function, Args}) when
    is_atom(Module), is_atom(Function), is_list(Args)
->
    try erlang:apply(Module, Function, [Topic | Args]) of
        true -> true;
        _ -> false
    catch
        _:_ -> false
    end;
do_is_quick_uplink_topic(_Topic, _) ->
    false.
