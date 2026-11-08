# Concepts

This page explains what this collector is for and how it behaves, in plain words. If you want the pictures, they're all on the [diagrams page](../diagrams/README.md), and section headings below link to the matching one.

## The short story

Eshu is the core system. A collector is a small helper program: it reads one outside source, turns what it finds into facts (small, typed records), and gives those facts back to Eshu. The [system context diagram](../diagrams/README.md#system-context) shows where this one sits.

A few words first, since supply-chain talk gets dense fast. An SBOM (software bill of materials) lists the parts inside one piece of software. An attestation is a signed statement about how software was built, and SLSA provenance is the build-history part of that statement: what built it, and from what inputs. A claim is one unit of work Eshu sends the collector.

One run covers one document, named by the claim. The collector fetches that one document over bounded HTTPS and parses it. Only Eshu core may later promote a parsed document to verified truth. This collector only reports what the document says, which is why every fact carries confidence `reported` plus where it came from: source system, scope, generation, a stable key, a cleaned source address, and a source record ID.

Registry-based discovery stays out of scope on purpose. Finding documents attached to container images (`oci_referrer` targets) is Eshu core's job, and this build refuses such targets at setup instead of silently skipping them, so missing coverage is loud rather than quiet.

## How a run can end

A run ends as `complete`, `retryable` (try again later, say after throttling or for a scope with no configured target), or `terminal` (stop, a person needs to fix the setup first). Requests are capped at 1 MiB and results at 32 MiB.

## The facts, in one breath

This collector returns its facts at schema `1.1.0` with confidence `reported`, which means the source said so and Eshu hasn't checked it directly. Every fact carries where it came from: source system, scope, generation, a stable key, a cleaned source address, and a source record ID. The full list lives in [the fact kinds reference](../reference/facts.md), which mirrors `manifest.yaml`.

## A worked example

This one comes straight from the test fixtures, so you can open the files yourself. The input document is [document/testdata/cyclonedx_image_subject.json](../../document/testdata/cyclonedx_image_subject.json): a CycloneDX 1.5 SBOM whose subject is a container image, `registry.example.com/library/example` at version `1.2.3`, with a `lodash` library component listed inside.

Say a claim names the scope configured for that document. The collector fetches it, parses it, and returns facts about the document itself plus one `sbom.component` fact per part it lists, dependency links between them, and any outside references. You can see the expected output shape in the parity fixture at [runtime/testdata/8865-parity-sbom-attestation.json](../../runtime/testdata/8865-parity-sbom-attestation.json), where the same image subject shows up as an `sbom.component` fact with its package URL, version `1.2.3`, and SHA-256 hash. Malformed and subject-less variants sit right beside the good fixture, and those cover the warning and failed-read paths.

## What it never does

It never writes, signs, or changes a document, and it stores nothing itself. The host validates and commits. It never follows a document to discover more documents, and it never serves `oci_referrer` targets. It never imports Eshu core internals (`github.com/eshu-hq/eshu/go/internal/...`); `boundary_test.go` fails the build if that changes. And it never puts credentials into facts, logs, source addresses, or status messages, nor promotes a document's claims to verified truth.

One more boundary worth knowing: all 8 fact kinds belong to Eshu core, so the host refuses them without a producer grant, which is written permission for this component to publish that kind. Eshu core issues grants. This repository mints none and carries no grant material.
