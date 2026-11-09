# Configuration

There's no example config file in this repository, and that's deliberate. The host passes the setup to the collector as the request `config` object (JSON), one claim at a time. So you'll write this JSON wherever you configure your Eshu host activations, not in a file that sits next to the binary.

The shape is small. One required top-level key names the setup, and a list of targets says which documents to serve.

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

Here's the shape with placeholder values:

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

Setup errors fail the claim as terminal `invalid_config` before any fetch. Error messages name the config key, never the value, so they're safe to log.

## Credentials

Secrets never go in the config. Instead, `username_env`, `password_env`, and `bearer_token_env` name environment variables the worker process already has. So `bearer_token_env: SBOM_FETCH_TOKEN` means "read the token from the variable called `SBOM_FETCH_TOKEN`."

A few guardrails keep this honest. Writing `username`, `password`, or `bearer_token` directly in the config is rejected. A named variable that's unset or blank also fails, so a typo can't silently turn a protected fetch into an anonymous one. A `document_url` that itself carries a login is refused too. The collector sends credentials only on the HTTP `Authorization` header (basic login or bearer token) of the document fetch, and the values never appear in facts, logs, or status messages.

## Time and size limits

Each claim has a deadline set by the host. One document fetch times out after 30 seconds, and the document body is capped by `max_bytes` (default 10 MiB). Server throttling (HTTP 429) and short-lived server failures return `retryable` with a suggested wait (`retry_after_seconds`; 60 seconds when the server gives none). Other 4xx answers are terminal. When in doubt, narrow the target rather than raising caps, since one claim is meant to cover exactly one document.
