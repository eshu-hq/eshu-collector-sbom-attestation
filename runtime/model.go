// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"time"

	sdkidentity "github.com/eshu-hq/eshu-sdk/factschema/identity"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/document"
)

// Provenance: collector identity and claim plumbing ported from
// go/internal/collector/sbom/runtime/source.go at core commit 695a0e0d9b,
// with the host-owned workflow.WorkItem exchanged for the published SDK
// claim at the NextClaimed boundary (SHIM_MAP section 1):
//
//   - ScopeID, GenerationID, CollectorInstanceID, and CollectorKind compare
//     against the same literals (was item.* on workflow.WorkItem).
//   - FencingToken arrives on the SDK claim as a string and must parse to a
//     positive int64, else collection fails closed (was
//     item.CurrentFencingToken).
//   - The claimed-status gate is dropped: a delivered SDK claim IS claimed
//     work; status lives host-side now.
//   - Generation metadata the SDK wire does not carry (pending status,
//     snapshot trigger) stays out of the snapshot; the SDK Generation
//     carries ID and observed time only.

// CollectorKind is the durable collector family name for SBOM attestation
// source facts (was scope.CollectorSBOMAttestation).
const CollectorKind = "sbom_attestation"

// ScopeKind names the hosted SBOM/attestation document scope (was
// scope.KindSBOMAttestation).
const ScopeKind = "sbom_attestation"

// workItem is the collector-side claim identity plumbed through envelope
// construction. NextClaimed builds exactly one from the validated SDK claim;
// the field names mirror workflow.WorkItem so the port diff stays mechanical.
type workItem struct {
	ScopeID             string
	GenerationID        string
	CollectorInstanceID string
	CollectorKind       string
	CurrentFencingToken int64
}

// ScopeInfo anchors the durable scope boundary for one collected snapshot.
type ScopeInfo struct {
	ScopeID       string
	ScopeKind     string
	CollectorKind string
}

// GenerationInfo anchors the durable generation boundary for one collected
// snapshot.
type GenerationInfo struct {
	GenerationID string
	ObservedAt   time.Time
}

// CollectedSnapshot is one collected scope generation: the boundary identity
// plus the emission envelopes in build order.
type CollectedSnapshot struct {
	Scope      ScopeInfo
	Generation GenerationInfo
	Envelopes  []Envelope
	Partial    bool
}

// Envelope is the runtime emission envelope. The document and attestation
// parsers build document.Envelope values; the runtime boundary converts them
// to SDK facts.
type Envelope = document.Envelope

// stableID returns a deterministic identifier for one fact-adjacent payload,
// resolving through the published factschema identity package.
func stableID(factType string, identity map[string]any) string {
	return sdkidentity.StableID(factType, identity)
}
