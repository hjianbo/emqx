%%--------------------------------------------------------------------
%% Copyright (c) 2026 EMQ Technologies Co., Ltd. All Rights Reserved.
%%--------------------------------------------------------------------

-module(emqx_dashboard_login_crypto).

-feature(maybe_expr, enable).

-include("emqx_dashboard.hrl").

-export([
    create_tables/0,
    negotiate_session_key/1,
    normalize_login_params/2,
    encrypt_login_response/2
]).

-define(BAD_REQUEST, 'BAD_REQUEST').
-define(PENDING_KEY_TAB, emqx_dashboard_login_pending_keys).
-define(PENDING_KEY_TTL_MS, 5 * 60 * 1000).

-record(login_pending_key, {
    key :: binary(),
    session_key :: binary(),
    expire_at :: integer()
}).

-spec create_tables() -> [atom()].
create_tables() ->
    ok = mria:create_table(?PENDING_KEY_TAB, [
        {type, set},
        {rlog_shard, ?DASHBOARD_SHARD},
        {storage, ram_copies},
        {record_name, login_pending_key},
        {attributes, record_info(fields, login_pending_key)}
    ]),
    [?PENDING_KEY_TAB].

-spec negotiate_session_key(map()) ->
    {ok, map()} | {error, {non_neg_integer(), atom(), binary()}}.
negotiate_session_key(Params) when is_map(Params) ->
    Conf = login_encryption_config(),
    Mode = maps:get(mode, Conf),
    case Mode of
        required ->
            maybe
                {ok, AesKey} ?= decrypt_negotiated_session_key(Params, Conf),
                {ok, KeyID} ?= cache_pending_session_key(AesKey),
                {ok, #{key_id => KeyID}}
            else
                {error, Msg} ->
                    bad_request(Msg)
            end;
        _ ->
            bad_request(<<"Login key API is only available when mode=required">>)
    end.

-spec normalize_login_params(term(), map()) ->
    {ok, map(), map()} | {error, {non_neg_integer(), atom(), binary()}}.
normalize_login_params(Body, Headers) when is_map(Headers) ->
    Conf = login_encryption_config(),
    Mode = maps:get(mode, Conf),
    case Mode of
        required ->
            maybe
                {ok, CiphertextB64} ?= parse_encrypted_login_body(Body),
                {ok, KeyID} ?= fetch_key_id(Headers),
                {ok, AesKey} ?= lookup_pending_session_key(KeyID),
                {ok, IV, Ciphertext, Tag} ?= decode_ciphertext_blob(CiphertextB64),
                {ok, PlainPayload} ?= decrypt_payload(AesKey, IV, Ciphertext, Tag),
                {ok, LoginParams} ?= decode_login_payload(PlainPayload),
                {ok, LoginParams, #{encrypted => true, session_key => AesKey}}
            else
                {error, Msg} ->
                    bad_request(Msg)
            end;
        _ ->
            maybe
                {ok, LoginParams} ?= parse_plain_login_params(Body),
                {ok, LoginParams, #{encrypted => false}}
            else
                {error, Msg} ->
                    bad_request(Msg)
            end
    end.

-spec encrypt_login_response(map(), binary()) -> {ok, binary()} | {error, binary()}.
encrypt_login_response(Response, SessionKey) when is_map(Response), is_binary(SessionKey) ->
    try
        IV = crypto:strong_rand_bytes(12),
        PlainPayload = emqx_utils_json:encode(Response),
        {Ciphertext, Tag} = crypto:crypto_one_time_aead(
            cipher_aesgcm256(),
            SessionKey,
            IV,
            PlainPayload,
            <<>>,
            true
        ),
        Blob = <<IV/binary, Tag/binary, Ciphertext/binary>>,
        {ok, base64:encode(Blob)}
    catch
        _:_ ->
            {error, <<"Failed to encrypt login response">>}
    end.

login_encryption_config() ->
    Raw = emqx:get_config([dashboard, login_encryption], #{}),
    Conf0 = maybe_to_map(Raw),
    Conf = normalize_keys(Conf0),
    #{
        mode => maps:get(mode, Conf, disabled),
        private_key => emqx_secret:unwrap(maps:get(private_key, Conf, <<>>))
    }.

normalize_keys(Conf) ->
    Mode0 = get_with_keys(Conf, [mode, <<"mode">>], undefined),
    Mode =
        case Mode0 of
            undefined -> mode_from_legacy(Conf);
            _ -> normalize_mode(Mode0)
        end,
    #{
        mode => Mode,
        private_key => get_with_keys(Conf, [private_key, <<"private_key">>], <<>>)
    }.

mode_from_legacy(Conf) ->
    Enable = get_with_keys(Conf, [enable, <<"enable">>], false),
    RequireEncryptedBody = get_with_keys(
        Conf,
        [require_encrypted_body, <<"require_encrypted_body">>],
        false
    ),
    case {Enable, RequireEncryptedBody} of
        {true, true} -> required;
        {true, false} -> optional;
        _ -> disabled
    end.

normalize_mode(required) -> required;
normalize_mode(optional) -> optional;
normalize_mode(disabled) -> disabled;
normalize_mode(<<"required">>) -> required;
normalize_mode(<<"optional">>) -> optional;
normalize_mode(<<"disabled">>) -> disabled;
normalize_mode(_) -> disabled.

get_with_keys(Map, [Key | Rest], Default) ->
    case maps:find(Key, Map) of
        {ok, Value} -> Value;
        error -> get_with_keys(Map, Rest, Default)
    end;
get_with_keys(_Map, [], Default) ->
    Default.

maybe_to_map(Map) when is_map(Map) ->
    Map;
maybe_to_map(_) ->
    #{}.

decrypt_negotiated_session_key(Params, Conf) ->
    maybe
        {ok, EncryptedKeyB64} ?= fetch_binary(Params, [<<"encrypted_key">>, encrypted_key]),
        {ok, EncryptedKey} ?= decode_base64(EncryptedKeyB64),
        {ok, PrivateKey} ?= load_private_key(maps:get(private_key, Conf, <<>>)),
        {ok, AesKey} ?= decrypt_aes_key(EncryptedKey, PrivateKey),
        {ok, AesKey}
    else
        {error, _} = Error ->
            Error
    end.

fetch_key_id(Headers) ->
    case find_first(Headers, [<<"x-dashboard-login-key-id">>]) of
        {ok, KeyID} when is_binary(KeyID), KeyID =/= <<>> ->
            {ok, KeyID};
        {ok, KeyID} when is_list(KeyID), KeyID =/= [] ->
            {ok, iolist_to_binary(KeyID)};
        {ok, _} ->
            {error, <<"Invalid key id header">>};
        error ->
            {error, <<"Missing login key id header">>}
    end.

decode_ciphertext_blob(CiphertextB64) ->
    maybe
        {ok, Blob} ?= decode_base64(CiphertextB64),
        true ?= byte_size(Blob) > 28,
        <<IV:12/binary, Tag:16/binary, Ciphertext/binary>> = Blob,
        {ok, IV, Ciphertext, Tag}
    else
        false ->
            {error, <<"Bad encrypted login payload format">>};
        _ ->
            {error, <<"Bad encrypted login payload format">>}
    end.

cache_pending_session_key(AesKey) ->
    KeyID = binary:encode_hex(crypto:strong_rand_bytes(16)),
    Now = erlang:system_time(millisecond),
    ok = cleanup_expired_pending_keys(Now),
    ExpireAt = Now + ?PENDING_KEY_TTL_MS,
    ok = mria:dirty_write(?PENDING_KEY_TAB, #login_pending_key{
        key = KeyID,
        session_key = AesKey,
        expire_at = ExpireAt
    }),
    {ok, KeyID}.

lookup_pending_session_key(KeyID) ->
    Now = erlang:system_time(millisecond),
    case mnesia:dirty_read(?PENDING_KEY_TAB, KeyID) of
        [#login_pending_key{session_key = AesKey, expire_at = ExpireAt}] when ExpireAt > Now ->
            ok = mria:dirty_delete(?PENDING_KEY_TAB, KeyID),
            {ok, AesKey};
        [#login_pending_key{}] ->
            ok = mria:dirty_delete(?PENDING_KEY_TAB, KeyID),
            {error, <<"Expired login key id">>};
        [] ->
            {error, <<"Unknown login key id">>}
    end.

cleanup_expired_pending_keys(Now) ->
    MatchSpec = [
        {
            {login_pending_key, '$1', '_', '$2'},
            [{'=<', '$2', Now}],
            ['$1']
        }
    ],
    Keys = mnesia:dirty_select(?PENDING_KEY_TAB, MatchSpec),
    lists:foreach(fun(Key) -> ok = mria:dirty_delete(?PENDING_KEY_TAB, Key) end, Keys),
    ok.

fetch_binary(Map, [Key | Rest]) ->
    case maps:find(Key, Map) of
        {ok, Value} when is_binary(Value), Value =/= <<>> -> {ok, Value};
        {ok, _Value} -> {error, <<"Invalid encrypted login field type">>};
        error -> fetch_binary(Map, Rest)
    end;
fetch_binary(_Map, []) ->
    {error, <<"Missing encrypted login field">>}.

decode_base64(Value) ->
    try
        {ok, base64:decode(Value)}
    catch
        error:_ ->
            {error, <<"Bad base64 in encrypted login body">>}
    end.

load_private_key(<<>>) ->
    {error, <<"Dashboard login_encryption.private_key is not configured">>};
load_private_key(PrivateKey0) when is_binary(PrivateKey0); is_list(PrivateKey0) ->
    PrivateKey = iolist_to_binary(PrivateKey0),
    Pem =
        case maybe_read_file(PrivateKey) of
            {ok, Content} -> Content;
            error -> PrivateKey
        end,
    try
        case public_key:pem_decode(Pem) of
            [Entry | _] ->
                {ok, public_key:pem_entry_decode(Entry)};
            [] ->
                {error, <<"Bad RSA private key PEM">>}
        end
    catch
        _:_ ->
            {error, <<"Bad RSA private key PEM">>}
    end.

maybe_read_file(Path) ->
    case filelib:is_file(Path) of
        true -> file:read_file(Path);
        false -> error
    end.

decrypt_aes_key(EncryptedKey, PrivateKey) ->
    try
        AesKey = public_key:decrypt_private(EncryptedKey, PrivateKey, [
            {rsa_padding, rsa_pkcs1_oaep_padding},
            {rsa_oaep_md, sha256},
            {rsa_mgf1_md, sha256}
        ]),
        case byte_size(AesKey) of
            32 -> {ok, AesKey};
            _ -> {error, <<"Invalid AES session key length">>}
        end
    catch
        _:_ ->
            {error, <<"Failed to decrypt AES session key">>}
    end.

decrypt_payload(AesKey, IV, Ciphertext, Tag) ->
    try
        {ok,
            crypto:crypto_one_time_aead(
                cipher_aesgcm256(), AesKey, IV, Ciphertext, <<>>, Tag, false
            )}
    catch
        _:_ ->
            {error, <<"Failed to decrypt login payload">>}
    end.

cipher_aesgcm256() ->
    erlang:binary_to_atom(<<"aes_256_gcm">>, utf8).

decode_login_payload(Payload) ->
    maybe
        {ok, Decoded} ?= emqx_utils_json:safe_decode(Payload),
        true ?= is_map(Decoded),
        {ok, Username} ?= fetch_binary(Decoded, [<<"username">>]),
        {ok, Password} ?= fetch_binary(Decoded, [<<"password">>]),
        LoginParams = maybe_put_mfa_token(Decoded, #{
            <<"username">> => Username,
            <<"password">> => Password
        }),
        {ok, LoginParams}
    else
        _ ->
            {error, <<"Bad decrypted login payload">>}
    end.

maybe_put_mfa_token(Decoded, Params) ->
    case maps:find(<<"mfa_token">>, Decoded) of
        {ok, MfaToken} when is_binary(MfaToken) ->
            Params#{<<"mfa_token">> => MfaToken};
        {ok, _} ->
            Params;
        error ->
            Params
    end.

parse_plain_login_params(Params) when is_map(Params) ->
    maybe
        {ok, Username} ?=
            fetch_plain_binary(Params, [<<"username">>, username], <<"Username is required">>),
        {ok, Password} ?=
            fetch_plain_binary(Params, [<<"password">>, password], <<"Password is required">>),
        {ok,
            maybe_put_mfa_token(Params, #{
                <<"username">> => Username,
                <<"password">> => Password
            })}
    end;
parse_plain_login_params(_Body) ->
    {error, <<"Plain login body must be JSON object">>}.

parse_encrypted_login_body(Body) when is_binary(Body), Body =/= <<>> ->
    {ok, Body};
parse_encrypted_login_body(Body) when is_list(Body), Body =/= [] ->
    {ok, iolist_to_binary(Body)};
parse_encrypted_login_body(_) ->
    {error, <<"Encrypted login body must be base64 string">>}.

fetch_plain_binary(Map, Keys, MissingError) ->
    case find_first(Map, Keys) of
        {ok, Value} when is_binary(Value), Value =/= <<>> ->
            {ok, Value};
        {ok, _} ->
            {error, <<"Username/password must be a non-empty binary">>};
        error ->
            {error, MissingError}
    end.

find_first(Map, [Key | Rest]) ->
    case maps:find(Key, Map) of
        {ok, Value} ->
            {ok, Value};
        error ->
            find_first(Map, Rest)
    end;
find_first(_Map, []) ->
    error.

bad_request(Message) ->
    {error, {400, ?BAD_REQUEST, Message}}.
