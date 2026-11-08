# Guides

Step-by-step help for the jobs you'll actually do with this collector. Each one assumes you've skimmed [getting started](../getting-started/README.md).

## Seed it into a component folder

The published image is `ghcr.io/eshu-hq/eshu-collector-sbom-attestation`. It holds one static binary with no shell, and the binary can install itself into a component folder, which is how a startup (init) container usually sets it up:

```bash
collector seed --dest /component [--image-ref ghcr.io/eshu-hq/eshu-collector-sbom-attestation@sha256:<digest>]
```

That writes `/component/collector` (mode 0755) and `/component/manifest.yaml`. The `--image-ref` flag, or the `COLLECTOR_IMAGE_REF` environment variable when the flag is absent, stamps the exact deployed image reference into the manifest. The flag wins when both are set. This step exists because an image can't contain its own digest, so the manifest in this repository keeps an all-zero placeholder digest on purpose. A bad image reference fails before any file is written. The [deployment diagram](../diagrams/README.md#deployment-and-seed) draws the whole flow.

## Operate it day to day

Start with the claim result. It's either `complete`, or it carries a failure class that tells you where to look: `invalid_config` means the setup is wrong and retrying won't help; `unknown_scope` means the claim names a scope no target covers, and it stays retryable so the coordinator can add the target later; `rate_limited` and `retryable` mean the document server pushed back, so let it retry with the suggested wait; `non_retryable` means the document or the answer can't become facts as-is.

The collector also writes one JSON diagnostic line per claim to standard error: `complete` with fact counts and latency, `failure` with class, HTTP status, and a bounded `result` such as `rate_limited`, plus `config_failure` and `unknown_scope`. The host keeps only the byte count and drops the text, so that line really helps only in a local run (`collector --sdk-stdio < request.json`) or in tests.

This collector emits no metrics of its own. The manifest declares the prefix `eshu_dp_sbom_attestation_collector_`, but nothing is emitted under it. Use the claim result as your operator signal.

## Troubleshoot a failing feed

If every claim comes back `invalid_config`, read the key named in the message first. It's usually a missing required target key, an `oci_referrer` target this build refuses, or a credential written inline where an environment reference belongs. If you see `unknown_scope`, check that some target's `scope_id` matches the claim exactly. Repeated `rate_limited` results point at the document server, not at your setup, so check its limits before touching caps.

## Release a new version

Releases run from `.github/workflows/release.yml` on every push to `main` and on version tags. Nothing runs for a pull request, and the workflow deploys nothing. A `main` push publishes the moving `main`, `latest`, and `sha-<full-sha>` image tags. Use moving tags only where floating is intended, and pin real deployments to digests.

To publish a version release, tag `v<manifest version>` on the protected `main` head. A `v<version>-*` suffix makes a pre-release, for example for QA. A tag on any other commit publishes nothing. The workflow pushes the image with build-provenance and SBOM attestations and reports the digest in the job summary. Copy that digest into the deployment's seed image reference.

Extraction background: [eshu-hq/eshu#8865](https://github.com/eshu-hq/eshu/issues/8865).
