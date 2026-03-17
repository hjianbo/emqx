%%--------------------------------------------------------------------
%% Copyright (c) 2026 EMQ Technologies Co., Ltd. All Rights Reserved.
%%--------------------------------------------------------------------

-module(emqx_dashboard_login_public_key_api).

-export([
    init/2,
    path/0
]).

path() ->
    emqx_dashboard_swagger:relative_uri("/login/public_key").

init(Req0, State) ->
    case cowboy_req:method(Req0) of
        <<"GET">> ->
            {StatusCode, Body} = get_public_key_response(),
            Req = reply_json(StatusCode, Body, Req0),
            {ok, Req, State};
        _ ->
            Req = reply_json(
                405,
                #{
                    code => <<"METHOD_NOT_ALLOWED">>,
                    message => <<"Method not allowed">>
                },
                Req0
            ),
            {ok, Req, State}
    end.

get_public_key_response() ->
    case emqx_dashboard_login_crypto:get_login_public_key() of
        {ok, Result} ->
            {200, #{public_key => maps:get(public_key, Result)}};
        {error, {StatusCode, Code, Message}} ->
            {StatusCode, #{
                code => erlang:atom_to_binary(Code, utf8),
                message => iolist_to_binary(Message)
            }}
    end.

reply_json(StatusCode, Body, Req0) ->
    cowboy_req:reply(
        StatusCode,
        #{<<"content-type">> => <<"application/json">>},
        emqx_utils_json:encode(Body),
        Req0
    ).
