# PR16331 Beam Patch Compatibility Assessment (e5.10.0 baseline)

## 1) Dependency updates observed in built artifacts

- `brod`: `4.3.1 -> 4.5.1`
- `wolff`: `4.0.9 -> 4.0.13`
- `kafka_protocol`: `4.2.3 -> 4.3.1`
- `crc32cer`: `0.1.12 -> 1.1.0`
- `brod_oauth`: baseline has `0.1.1`, target build has no compiled `brod_oauth` app directory

Sources:
- `apps/emqx_bridge_azure_event_hub/rebar.config`
- `apps/emqx_bridge_confluent/rebar.config`
- `apps/emqx_bridge_kafka/rebar.config`

## 2) EMQX repository runtime code updates (non-test)

- `apps/emqx_bridge_kafka/src/emqx_bridge_kafka_impl_consumer.erl`
- `apps/emqx_bridge_kafka/src/emqx_bridge_kafka_consumer_sup.erl`

(Other changed files are tests/scripts/config metadata and do not produce runtime BEAM behavior directly.)

## 3) Data / internal state compatibility assessment

### Persistent data compatibility

- No Mnesia schema, durable storage format, or on-disk payload format changes are introduced in the changed runtime modules above.
- Conclusion: **persistent data compatibility risk is low**.

### In-memory state compatibility

- Connector/source state is still map-based and key set remains compatible (`installed_sources`, `kafka_client_id`, `subscriber_id`, `kafka_topics`) in the updated code path.
- Health-check logic changed from partition leader probing to consumer-group health probing, including `rebalancing -> connecting` status behavior.
- Dry-run path now skips spawning subscriber workers and uses connectivity probe only.

Operational impact:

- Existing running consumer workers should be restarted/recreated when applying this patch (disable/enable source/connector or restart node) to avoid stale runtime process assumptions.

### Important risk note (MSK IAM path)

- Kafka implementation still references `brod_oauth` for `msk_iam` auth path (`apps/emqx_bridge_kafka/src/emqx_bridge_kafka_impl.erl`), but target build output does not contain a new `brod_oauth` app directory.
- For BEAM patch rollout on top of existing e5.10.x nodes, keep existing `brod_oauth` files intact; do not remove them.
- If building full release artifacts from this branch, verify `brod_oauth` presence before deployment.

## 4) Build caveat handled

- A local compile adaptation was required due macro name collision with `emqx_resource.hrl`:
  - `apps/emqx_bridge_kafka/src/emqx_bridge_kafka_impl_consumer.erl`
  - local macro renamed to avoid redefining `HEALTHCHECK_TIMEOUT`.
