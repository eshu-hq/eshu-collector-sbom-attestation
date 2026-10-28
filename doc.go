// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package collector is the standalone SBOM attestation collector
// entrypoint surface: the process adapter the Eshu component-extension host
// runs. The host writes one bounded collector-sdk/v1alpha1 request to stdin
// and reads one result from stdout. The collector gets no Postgres, graph,
// queue, lease, workflow, or telemetry handle, and it never imports
// github.com/eshu-hq/eshu/go/internal/... (boundary_test.go enforces this).
// The host builds the core fact envelope, validates the result, and owns
// claims and commits.
//
// Claim flow: Handler parses the request config into a runtime.SourceConfig,
// serves the named scope through runtime.ClaimedSource, and converts the
// snapshot with runtime.ToSDKResult. Document parsing stays in document/,
// source redaction in urlredact/, and stable identity in packageidentity/.
package collector

// Probe: Go-only comment change to prove the image lane selects go-class PRs.
