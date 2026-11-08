# Fact kinds

This table mirrors the `emittedFacts` list in [manifest.yaml](../../manifest.yaml). "Mirrors" matters: the manifest is the source of truth, and this page explains it in friendlier words. If you change one, update the other in the same change so they never drift apart.

Every kind below sits at schema `1.1.0` with confidence `reported`, meaning the source said so and Eshu hasn't checked it directly. Every fact carries where it came from: source system, scope, generation, a stable key, a cleaned source address, and a source record ID.

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

Supported inputs are SBOM documents in CycloneDX JSON or SPDX JSON, and attestation statements in in-toto JSON, including SLSA provenance details and signature check results. Problems inside a document become `sbom.warning` facts instead of failing the whole run, so you still get the parts that parsed cleanly.

All of these kinds belong to Eshu core, so the host refuses them without a producer grant (written permission for this component to publish that kind). Eshu core issues grants. This repository mints none.

For the story behind the table, including a worked example from the test fixtures, see [concepts](../concepts/README.md).
