# Beam Patch Artifacts for PR #16331 (backport to e5.10.0)

This directory contains compiled BEAM artifacts collected from branch `hotfix/pr_16331_on_e5.10.0`, compared against baseline `e5.10.0`.

- Manifest (file list + sha256): `MANIFEST.txt`
- Compatibility assessment: `COMPATIBILITY_ASSESSMENT.md`

Scope of BEAM artifacts in this folder:
- `emqx_bridge_kafka` (runtime changed modules)
- dependency BEAMs changed by backport: `brod`, `wolff`, `kafka_protocol`, `crc32cer`

Note: `brod_oauth` is not included here; keep existing runtime `brod_oauth` in deployment package for MSK IAM path.
