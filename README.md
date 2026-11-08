# eshu-collector-sbom-attestation

Status: pre-release. Do not rely on it in production yet.

This collector reads one software-supply-chain document — an SBOM or an attestation — and hands Eshu a checked summary of what the document says.

Eshu is the core system. A collector is a small helper program: it reads one outside source, turns what it finds into facts (small, typed records), and gives those facts back to Eshu. This collector only reads documents. It never changes them.

Words used below: an SBOM (software bill of materials) is a list of the parts inside one piece of software. An attestation is a signed statement about how software was built. SLSA provenance is the build-history part of such a statement: what built it, from what inputs. A claim is one unit of work Eshu sends the collector.

## What it collects

One run covers one document, named by the claim. The collector fetches that one document over bounded HTTPS and parses it. It supports:

- SBOM documents in CycloneDX JSON or SPDX JSON (two common SBOM formats);
- attestation statements in in-toto JSON, including SLSA provenance details and signature check results.

It returns 8 fact kinds, all at schema `1.1.0` with confidence `reported` (the source document said so; Eshu did not check it directly):

| Fact kind | One fact describes |
| --- | --- |
| `sbom.document` | one parsed or attempted SBOM document |
| `sbom.component` | one part listed in an SBOM |
| `sbom.dependency_relationship` | one "part A depends on part B" link |
| `sbom.external_reference` | one outside link or ID named by an SBOM |
| `attestation.statement` | one attestation statement envelope |
| `attestation.slsa_provenance` | one SLSA build-history statement |
| `attestation.signature_verification` | one signature check result |
| `sbom.warning` | one non-fatal parsing problem |

Problems inside a document become `sbom.warning` facts instead of failing the whole run. Only Eshu core may later promote a parsed document to verified truth; this collector only reports what the document says.

A run ends as `complete`, `retryable` (try again later — for example, the claim names a scope with no configured target, or the document server throttled or failed in a short-lived way), or `terminal` (stop; a person must fix the setup first). Every fact carries where it came from: source system, scope, generation, a stable key, a cleaned source address, and a source record ID.

## How data flows

```mermaid
flowchart LR
  A["Configured document URL"] --> B["This collector"] --> C["Eshu host process"] --> D["Eshu core"]
```

Text version: configured document URL → this collector → Eshu host process (checks and stores the result) → Eshu core. The collector never talks to Eshu's database directly.

## When to use it, and when not to

Use it when Eshu needs the contents of SBOM or attestation documents that already exist at known web addresses, read on a schedule Eshu controls. Do not use it to create or sign documents, to scan software and build an SBOM from scratch, or to discover documents attached to container images: registry-based discovery (`oci_referrer` targets) stays in Eshu core, and this build refuses such targets instead of silently skipping them.

## How Eshu runs it

Eshu's component host starts this program for one claim at a time: it sends one bounded `collector-sdk/v1alpha1` request on standard input (stdin) and reads one result from standard output (stdout). Requests are capped at 1 MiB and results at 32 MiB.

```bash
collector --sdk-stdio   # serve one claim from stdin
```

The collector gets no database, graph, queue, lease, workflow, or metrics handle. The host builds the final fact envelope (the wrapper Eshu stores), checks the result, and owns claims and commits.

The published image is `ghcr.io/eshu-hq/eshu-collector-sbom-attestation`. It holds one static binary with no shell, and the binary can install itself into a component folder (how a startup, or init, container sets it up):

```bash
collector seed --dest /component [--image-ref ghcr.io/eshu-hq/eshu-collector-sbom-attestation@sha256:<digest>]
```

This writes `/component/collector` (mode 0755) and `/component/manifest.yaml`. `--image-ref` (or the `COLLECTOR_IMAGE_REF` environment variable; the flag wins) stamps the exact deployed image reference into the manifest, because an image cannot contain its own digest. The manifest in this repository keeps an all-zero placeholder digest on purpose. A bad image reference fails before any file is written. `scripts/pin-digest.sh <repo:tag>` only prints the `repo@sha256:...` reference of a pushed image; it edits nothing.

## Configuration

There is no example config file in this repository. The host passes the setup as the request `config` object (JSON). It has one required top-level key plus a list of targets:

| Key | Meaning |
| --- | --- |
| `collector_instance_id` | Required. Names this collector setup |
| `targets` | List of targets. Each claim serves the one target whose `scope_id` matches the claim |

Each target uses these keys:

| Target key | Meaning |
| --- | --- |
| `scope_id` | Required. The claim scope this target serves; part of every stored fact key, so choose it once and keep it |
| `source_type` | Required. Only `configured_source` is served; `oci_referrer` is refused |
| `artifact_kind` | Required. `sbom` or `attestation` |
| `document_format` | Required. `cyclonedx` or `spdx` for SBOMs; `in_toto` for attestations |
| `document_url` | Required for `configured_source`. The web address to fetch |
| `source_uri`, `source_record_id` | Optional provenance labels; sensible values are filled in from the URL and scope when left empty |
| `provider`, `registry` | Optional labels naming where the document lives |
| `subject_digest`, `referrer_digest` | Optional digests of the software and document the facts describe |
| `verification_result`, `verification_policy` | Optional signature-check result and the policy it was checked against |
| `max_bytes` | Optional size cap for the fetched document. Default 10 MiB; an oversize document fails instead of being cut short |
| `username_env`, `password_env`, `bearer_token_env` | Optional. Names of environment variables that hold fetch credentials (see below) |

Example shape (values are placeholders):

```json
{
  "collector_instance_id": "sbom-1",
  "targets": [{
    "scope_id": "sbom:example/app",
    "source_type": "configured_source",
    "artifact_kind": "sbom",
    "document_format": "cyclonedx",
    "document_url": "https://example.com/app.cdx.json",
    "bearer_token_env": "SBOM_FETCH_TOKEN"
  }]
}
```

Setup errors fail the claim as terminal `invalid_config` before any fetch. Error messages name the config key, never the value, so they are safe to log.

## Credentials

Secrets never go in the config. `username_env`, `password_env`, and `bearer_token_env` name environment variables the worker process already has — for example, `bearer_token_env: SBOM_FETCH_TOKEN` means "read the token from the variable called `SBOM_FETCH_TOKEN`." The collector sends them only on the HTTP `Authorization` header (basic login or bearer [REDACTED]) of the document fetch. Writing `username`, `password`, or `bearer_token` directly in the config is rejected. A named variable that is unset or blank also fails, so a typo cannot silently turn a protected fetch into an anonymous one. A `document_url` that itself carries a login is refused. Credential values never appear in facts, logs, or status messages.

## Time and size limits

Each claim has a deadline set by the host. One document fetch times out after 30 seconds, and the document body is capped by `max_bytes` (default 10 MiB). Server throttling (HTTP 429) and short-lived server failures return `retryable` with a suggested wait (`retry_after_seconds`; 60 seconds when the server gives none). Other 4xx answers are terminal.

## What operators see

The main signal is the claim result: `complete`, or a failure class such as `invalid_config` (fix the setup), `unknown_scope` (the claim names a scope no target covers; it stays retryable so the coordinator can add it later), `rate_limited`, `retryable`, or `non_retryable`.

The collector also writes one JSON diagnostic line per claim to standard error (stderr): `complete` with fact counts and latency, `failure` with class, HTTP status, and a bounded `result` such as `rate_limited`, plus `config_failure` and `unknown_scope`. The host keeps only the byte count and drops the text, so that line helps only in a local run (`collector --sdk-stdio < request.json`) or in tests.

This collector emits no metrics of its own. The manifest declares the prefix `eshu_dp_sbom_attestation_collector_`, but nothing is emitted under it; use the claim result as the operator signal.

## Permission to publish facts

All 8 fact kinds belong to Eshu core, so the host refuses them without a producer grant (written permission for this component to publish that kind). Eshu core issues grants; this repository mints none and carries no grant material.

## Eshu dependencies

Exact versions from `go.mod`. Do not substitute another SDK line.

| Module | Version |
| --- | --- |
| Go | `1.26.10` |
| `github.com/eshu-hq/eshu-sdk/collector` | `v0.1.0-rc.4` |
| `github.com/eshu-hq/eshu-sdk/factschema` | `v0.1.0-rc.7` |
| `gopkg.in/yaml.v3` | `v3.0.1` |

The component ID is `dev.eshu.collector.sbom-attestation`, version `0.1.1`, collector kind `sbom_attestation`. It declares support for Eshu core `>=0.0.5 <0.2.0` and speaks `collector-sdk/v1alpha1` over the process adapter (see `manifest.yaml`). Check that range against your core version before enabling it; a mismatch makes the host refuse the component.

## What it never does

- It never writes, signs, or changes a document, and it never stores anything itself — the host validates and commits.
- It never follows a document to discover more documents, and it never serves `oci_referrer` targets; they fail at setup so missing coverage is loud, not silent.
- It never imports Eshu core internals (`github.com/eshu-hq/eshu/go/internal/...`); `boundary_test.go` fails the build if that changes.
- It never puts credentials into facts, logs, source addresses, or status messages, and it never promotes a document's claims to verified truth — that decision stays in Eshu core.

## Build, test, and release

```bash
make ci          # lint + test + race; the full local check CI runs
make lint        # vet, golangci-lint, format check, tidy check, 500-line cap
make test        # build + full test suite
make race        # race suite + coverage floor
make actionlint  # workflow lint
```

Releases run from `.github/workflows/release.yml` on every push to `main` and on version tags. Nothing runs for a pull request, and the workflow deploys nothing. A `main` push publishes the moving `main`, `latest`, and `sha-<full-sha>` image tags — use moving tags only where floating is intended and pin real deployments to digests. Tag `v<manifest version>` on the protected `main` head to publish a version release (a `v<version>-*` suffix makes a pre-release, for example for QA); a tag on any other commit publishes nothing. The workflow pushes `ghcr.io/eshu-hq/eshu-collector-sbom-attestation` with build-provenance and SBOM attestations and reports the digest in the job summary. Copy that digest into the deployment's seed image reference (`collector seed --image-ref <repo>@sha256:<digest>`).

Extraction background: [eshu-hq/eshu#8865](https://github.com/eshu-hq/eshu/issues/8865).

## Docs and related projects

- `manifest.yaml` — component identity, fact list, and core range. `Dockerfile` — the static distroless image. `doc.go` — the package boundary in code form.
- [Eshu core](https://github.com/eshu-hq/eshu) — the host that runs this collector.
- [eshu-sdk](https://github.com/eshu-hq/eshu-sdk) — shared SDK modules.
- [eshu-deploy](https://github.com/eshu-hq/eshu-deploy) — deployment examples and reference setups.

## Contributing

See `CONTRIBUTING.md`. In short: run `make ci` before pushing; it runs the same lint, test, and race checks as CI. Credentials travel by env reference, never inline, and are never logged.

## License

MIT. See `LICENSE`.
