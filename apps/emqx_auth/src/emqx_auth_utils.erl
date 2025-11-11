%%--------------------------------------------------------------------
%% Copyright (c) 2024-2025 EMQ Technologies Co., Ltd. All Rights Reserved.
%%--------------------------------------------------------------------

-module(emqx_auth_utils).

-export([
    cached_simple_sync_query/4
]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

-spec cached_simple_sync_query(
    emqx_auth_cache:name(),
    emqx_auth_cache:cache_key(),
    emqx_resource:resource_id(),
    _Request :: term()
) -> term().
cached_simple_sync_query(CacheName, CacheKey, ResourceID, Query) ->
    Fun = fun() ->
        case emqx_resource:simple_sync_query(ResourceID, eval_query(Query)) of
            {error, _} = Error ->
                {nocache, Error};
            Result ->
                {cache, Result}
        end
    end,
    emqx_auth_cache:with_cache(CacheName, CacheKey, fun() ->
        with_disc_cache(CacheName, CacheKey, Fun)
    end).

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

eval_query(Query) when is_function(Query, 0) ->
    Query();
eval_query(Query) ->
    Query.

with_disc_cache(emqx_authn_cache, CacheKey, Fun) ->
    case erlang:function_exported(emqx_whc_hacker, authn_cached_query, 2) of
        true ->
            emqx_whc_hacker:authn_cached_query(CacheKey, Fun);
        false ->
            Fun()
    end;
with_disc_cache(_, _, Fun) ->
    Fun().
