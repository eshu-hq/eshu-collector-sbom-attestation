# eshu-collector-sbom-attestation

Eshu sbom attestation collector, extracted from the Eshu core repository.

**Pre-release. Holds no producer authority until its reviewed cutover
(eshu-hq/eshu#8865).**

Extraction tracking: [eshu-hq/eshu#8865](https://github.com/eshu-hq/eshu/issues/8865).
The in-tree extraction census, producer-grant draft, and parity proofs live
in the core repository until the cutover rehearsal lands them here.

The collector runs through the Eshu component-extension host with the
`process` runner. The host writes one bounded `collector-sdk/v1alpha1` request
to stdin and reads one result from stdout. The collector gets no Postgres,
graph, queue, lease, workflow, or telemetry handle, and it never imports
`github.com/eshu-hq/eshu/go/internal/...` (`boundary_test.go` enforces this).
The host builds the core fact envelope, validates the result, and owns claims
and commits.

## What it collects

For the SBOM or attestation target named by the claim it fetches, over
bounded HTTPS, one explicitly configured document:

- CycloneDX or SPDX SBOM documents, parsed into the `sbom.*` kinds;
- in-toto attestation statements (including SLSA provenance predicates and
  signature verification results), parsed into the `attestation.*` kinds.

It emits the eight core `sbom.*`/`attestation.*` kinds at schema `1.1.0`, all
reported confidence. Parser-level problems surface as in-band `sbom.warning`
facts; only the reducer may promote a parsed document to verified truth.
Credentials resolve only from the environment at startup into runtime-only
target fields (HTTP `Authorization` header); they never reach facts, logs,
metric labels, or docs. Inline credential keys in the activation config are
rejected.

Result states: `complete`; `retryable` for unconfigured scopes and transient
or throttled provider failures; `terminal` for invalid config and
non-retryable provider failures. Every emitted envelope carries provenance:
source system, scope, generation, stable key, sanitized source URI, and
source record ID. The standalone image serves `configured_source` targets
only; `oci_referrer` discovery stays core-side and fails closed at admission.

## Operator signals

The collector declares the `eshu_dp_sbom_attestation_collector_` metric
prefix but emits nothing under it. Each claim writes one JSON diagnostic line
to stderr (kept only as a byte count by the process runner): `complete` with
fact counts and latency, `failure` with class, HTTP status, and a bounded
`result` such as `rate_limited`, plus `config_failure` and `unknown_scope`.

## Releasing

Tag `v<manifest version>` to publish the image. Use a `v<manifest
version>-*` prerelease (for example `v0.1.0-qa.1`) for QA images: the release
workflow publishes `ghcr.io/eshu-hq/eshu-collector-sbom-attestation` with
build-provenance and SBOM attestations, and reports the digest in the job
summary. Copy that digest into the activation's seed image reference
(`collector seed --image-ref <repo>@sha256:<digest>`). See
`scripts/pin-digest.sh` for resolving a pushed tag to its digest reference.

<!-- skip-proof: docs-only lane selection probe, closed unmerged. -->
