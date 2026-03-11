%%--------------------------------------------------------------------
%% Copyright (c) 2026 EMQ Technologies Co., Ltd. All Rights Reserved.
%%--------------------------------------------------------------------

-module(emqx_dashboard_login_encryption_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-import(
    emqx_mgmt_api_test_util,
    [
        uri/1,
        request_api/6
    ]
).

-include_lib("eunit/include/eunit.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("emqx_dashboard.hrl").

-define(USERNAME, <<"admin">>).
-define(PASSWORD, <<"public_www1">>).
-define(PENDING_KEY_TAB, emqx_dashboard_login_pending_keys).

all() ->
    emqx_common_test_helpers:all(?MODULE).

init_per_suite(Config) ->
    SuiteApps = emqx_cth_suite:start(
        [
            emqx_conf,
            emqx_management,
            emqx_mgmt_api_test_util:emqx_dashboard()
        ],
        #{work_dir => emqx_cth_suite:work_dir(Config)}
    ),
    [{suite_apps, SuiteApps} | Config].

end_per_suite(Config) ->
    emqx_cth_suite:stop(?config(suite_apps, Config)).

init_per_testcase(_TestCase, Config) ->
    mnesia:clear_table(?ADMIN),
    mnesia:clear_table(?ADMIN_JWT),
    mnesia:clear_table(?PENDING_KEY_TAB),
    emqx_dashboard_admin:add_user(
        ?USERNAME, ?PASSWORD, ?ROLE_SUPERUSER, <<"simple_description">>
    ),
    {PublicKey, PrivateKeyPem} = gen_rsa_keypair(),
    ok = set_login_encryption(required, PrivateKeyPem),
    [
        {public_key, PublicKey},
        {private_key_pem, PrivateKeyPem}
        | Config
    ].

end_per_testcase(_TestCase, Config) ->
    ok = set_login_encryption(disabled, <<>>),
    mnesia:clear_table(?ADMIN_JWT),
    mnesia:clear_table(?PENDING_KEY_TAB),
    Config.

t_encrypted_login_success(Config) ->
    PublicKey = ?config(public_key, Config),
    {KeyID, SessionKey} = negotiate_key(PublicKey),
    CiphertextB64 = encrypted_login_body(?USERNAME, ?PASSWORD, SessionKey),
    {ok, EncryptedResponseB64} =
        api_post_raw_base64([login], CiphertextB64, [login_key_header(KeyID)]),
    ?assert(is_binary(EncryptedResponseB64)),
    ?assertMatch(
        {ok, #{<<"token">> := _}},
        decrypt_login_response(EncryptedResponseB64, SessionKey)
    ).

t_plain_login_works_when_optional(_) ->
    ok = set_login_encryption(optional, <<>>),
    ?assertMatch(
        {ok, #{<<"token">> := _}},
        api_post([login], #{username => ?USERNAME, password => ?PASSWORD})
    ).

t_plain_login_rejected_when_required(Config) ->
    PrivateKeyPem = ?config(private_key_pem, Config),
    ok = set_login_encryption(required, PrivateKeyPem),
    ?assertMatch(
        {error, 400, #{<<"code">> := <<"BAD_REQUEST">>}},
        api_post([login], #{username => ?USERNAME, password => ?PASSWORD})
    ).

t_json_ciphertext_wrapper_rejected_when_required(Config) ->
    PublicKey = ?config(public_key, Config),
    {KeyID, SessionKey} = negotiate_key(PublicKey),
    CiphertextB64 = encrypted_login_body(?USERNAME, ?PASSWORD, SessionKey),
    ?assertMatch(
        {error, 400, #{<<"code">> := <<"BAD_REQUEST">>}},
        api_post(
            [login],
            #{ciphertext => CiphertextB64},
            [login_key_header(KeyID)]
        )
    ).

t_key_agreement_rejected_when_not_required(Config) ->
    PublicKey = ?config(public_key, Config),
    ok = set_login_encryption(optional, <<>>),
    Body = key_agreement_body(PublicKey, crypto:strong_rand_bytes(32)),
    ?assertMatch(
        {error, 400, #{<<"code">> := <<"BAD_REQUEST">>}},
        api_post([login, key], Body)
    ).

t_encrypted_login_bad_ciphertext(Config) ->
    PublicKey = ?config(public_key, Config),
    {KeyID, SessionKey} = negotiate_key(PublicKey),
    _Body = encrypted_login_body(?USERNAME, ?PASSWORD, SessionKey),
    BrokenCiphertext = base64:encode(crypto:strong_rand_bytes(16)),
    ?assertMatch(
        {error, 400, #{<<"code">> := <<"BAD_REQUEST">>}},
        api_post_raw_base64([login], BrokenCiphertext, [login_key_header(KeyID)])
    ).

t_login_stores_aes_session_key_in_token_extra(Config) ->
    PublicKey = ?config(public_key, Config),
    {KeyID, SessionKey} = negotiate_key(PublicKey),
    CiphertextB64 = encrypted_login_body(?USERNAME, ?PASSWORD, SessionKey),
    {ok, EncryptedResponseB64} = api_post_raw_base64(
        [login], CiphertextB64, [login_key_header(KeyID)]
    ),
    {ok, #{<<"token">> := Token}} = decrypt_login_response(EncryptedResponseB64, SessionKey),
    {ok, #?ADMIN_JWT{extra = Extra}} = emqx_dashboard_token:lookup(Token),
    ?assertEqual(SessionKey, maps:get(login_aes_key, Extra)).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

set_login_encryption(Mode, PrivateKeyPem) ->
    emqx_config:put([dashboard, login_encryption], #{
        mode => Mode,
        private_key => PrivateKeyPem
    }).

gen_rsa_keypair() ->
    PrivateKey = public_key:generate_key({rsa, 2048, 17}),
    PublicKey = #'RSAPublicKey'{
        modulus = PrivateKey#'RSAPrivateKey'.modulus,
        publicExponent = PrivateKey#'RSAPrivateKey'.publicExponent
    },
    PrivateDer = public_key:der_encode('RSAPrivateKey', PrivateKey),
    PrivatePem = public_key:pem_encode([{'RSAPrivateKey', PrivateDer, not_encrypted}]),
    {PublicKey, iolist_to_binary(PrivatePem)}.

negotiate_key(PublicKey) ->
    AesKey = crypto:strong_rand_bytes(32),
    Body = key_agreement_body(PublicKey, AesKey),
    {ok, #{<<"key_id">> := KeyID}} = api_post([login, key], Body),
    {KeyID, AesKey}.

key_agreement_body(PublicKey, AesKey) ->
    EncryptedKey = public_key:encrypt_public(AesKey, PublicKey, [
        {rsa_padding, rsa_pkcs1_oaep_padding},
        {rsa_oaep_md, sha256},
        {rsa_mgf1_md, sha256}
    ]),
    #{<<"encrypted_key">> => base64:encode(EncryptedKey)}.

encrypted_login_body(Username, Password, AesKey) ->
    IV = crypto:strong_rand_bytes(12),
    LoginPayload = emqx_utils_json:encode(#{username => Username, password => Password}),
    {CipherText, Tag} = crypto:crypto_one_time_aead(
        aes_256_gcm,
        AesKey,
        IV,
        LoginPayload,
        <<>>,
        true
    ),
    Blob = <<IV/binary, Tag/binary, CipherText/binary>>,
    base64:encode(Blob).

decrypt_login_response(ResponseCiphertextB64, AesKey) ->
    try
        Blob = base64:decode(ResponseCiphertextB64),
        true = byte_size(Blob) > 28,
        <<IV:12/binary, Tag:16/binary, CipherText/binary>> = Blob,
        PlainPayload = crypto:crypto_one_time_aead(
            aes_256_gcm,
            AesKey,
            IV,
            CipherText,
            <<>>,
            Tag,
            false
        ),
        emqx_utils_json:safe_decode(PlainPayload)
    catch
        _:_ ->
            {error, bad_login_response_ciphertext}
    end.

api_post(Path, Data) ->
    api_post(Path, Data, []).

api_post(Path, Data, ExtraHeaders) ->
    Headers = [noauth_header() | ExtraHeaders],
    case request_api(post, uri(Path), [], Headers, Data, post_request_opts()) of
        {ok, Code, ResponseBody} when Code >= 200 andalso Code =< 299 ->
            Res =
                case emqx_utils_json:safe_decode(ResponseBody) of
                    {ok, Decoded} -> Decoded;
                    {error, _} -> ResponseBody
                end,
            {ok, Res};
        {ok, Code, Body} ->
            Decoded =
                case emqx_utils_json:safe_decode(Body) of
                    {ok, Data0} -> Data0;
                    {error, _} -> Body
                end,
            {error, Code, Decoded}
    end.

api_post_raw_base64(Path, CiphertextB64, ExtraHeaders) ->
    Headers = [noauth_header() | ExtraHeaders],
    Opts = (post_request_opts())#{'content-type' => "text/plain"},
    case request_api(post, uri(Path), [], Headers, {raw, CiphertextB64}, Opts) of
        {ok, Code, ResponseBody} when Code >= 200 andalso Code =< 299 ->
            Res =
                case emqx_utils_json:safe_decode(ResponseBody) of
                    {ok, Decoded} -> Decoded;
                    {error, _} -> ResponseBody
                end,
            {ok, Res};
        {ok, Code, Body} ->
            Decoded =
                case emqx_utils_json:safe_decode(Body) of
                    {ok, Data0} -> Data0;
                    {error, _} -> Body
                end,
            {error, Code, Decoded};
        {error, {{_HttpVer, Code, _Message}, _RespHeaders, Body}} ->
            Decoded =
                case emqx_utils_json:safe_decode(Body) of
                    {ok, Data0} -> Data0;
                    {error, _} -> Body
                end,
            {error, Code, Decoded}
    end.

post_request_opts() ->
    #{
        compatible_mode => true,
        httpc_req_opts => [{body_format, binary}]
    }.

login_key_header(KeyID) ->
    {"x-dashboard-login-key-id", binary_to_list(KeyID)}.

noauth_header() ->
    emqx_common_test_http:auth_header("invalid", "password").
