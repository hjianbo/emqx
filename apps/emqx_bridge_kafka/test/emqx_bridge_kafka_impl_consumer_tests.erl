-module(emqx_bridge_kafka_impl_consumer_tests).

-include_lib("eunit/include/eunit.hrl").

traceparent_injection_test() ->
    Traceparent = <<"00-4bf92f3577b34da6a3ce929d0e0e4736-a3ce929d0e0e4736-01">>,
    Headers = emqx_bridge_kafka_impl_consumer:mqtt_headers_from_kafka_headers(#{
        <<"traceparent">> => Traceparent,
        <<"other">> => <<"value">>
    }),
    ?assertEqual(
        #{
            properties => #{
                'User-Property' => [{<<"traceparent">>, Traceparent}]
            }
        },
        Headers
    ).

traceparent_case_insensitive_injection_test() ->
    Traceparent = <<"00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01">>,
    Headers = emqx_bridge_kafka_impl_consumer:mqtt_headers_from_kafka_headers(#{
        <<"TraceParent">> => Traceparent
    }),
    ?assertEqual(
        #{
            properties => #{
                'User-Property' => [{<<"traceparent">>, Traceparent}]
            }
        },
        Headers
    ).

traceparent_absent_test() ->
    ?assertEqual(
        #{},
        emqx_bridge_kafka_impl_consumer:mqtt_headers_from_kafka_headers(#{<<"k">> => <<"v">>})
    ).

legacy_mqtt_message_with_headers_test() ->
    Traceparent = <<"00-11111111111111111111111111111111-2222222222222222-01">>,
    Headers = #{
        properties => #{
            'User-Property' => [{<<"traceparent">>, Traceparent}]
        }
    },
    Msg = emqx_bridge_kafka_impl_consumer:build_legacy_mqtt_message(
        <<"source:kafka_consumer:test">>,
        1,
        <<"/t">>,
        <<"p">>,
        Headers
    ),
    Props = emqx_message:get_header(properties, Msg, #{}),
    ?assertEqual([{<<"traceparent">>, Traceparent}], maps:get('User-Property', Props, [])).

legacy_mqtt_message_without_headers_test() ->
    Msg = emqx_bridge_kafka_impl_consumer:build_legacy_mqtt_message(
        <<"source:kafka_consumer:test">>,
        1,
        <<"/t">>,
        <<"p">>,
        #{}
    ),
    ?assertEqual(#{}, emqx_message:get_header(properties, Msg, #{})).
