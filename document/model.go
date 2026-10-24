// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package document

import (
	"time"

	sdkidentity "github.com/eshu-hq/eshu-sdk/factschema/identity"
)

// Provenance: envelope shape ported from go/internal/facts/models.go at core
// commit 695a0e0d9b. The collector owns its emission envelope; the SDK Fact
// mapping happens at the runtime boundary. stableID resolves through the
// published factschema identity package, whose StableID body is identical to
// the in-tree one; the parity proof pins byte-identical IDs.

// SourceConfidenceReported marks facts returned by an external system.
const SourceConfidenceReported = "reported"

// Ref identifies the source-local record that produced one fact.
type Ref struct {
	SourceSystem   string
	ScopeID        string
	GenerationID   string
	FactKey        string
	SourceURI      string
	SourceRecordID string
}

// Envelope is the durable Go representation of a fact envelope.
type Envelope struct {
	FactID           string
	ScopeID          string
	GenerationID     string
	FactKind         string
	StableFactKey    string
	SchemaVersion    string
	CollectorKind    string
	FencingToken     int64
	SourceConfidence string
	ObservedAt       time.Time
	Payload          map[string]any
	IsTombstone      bool
	SourceRef        Ref
}

// stableID returns a deterministic identifier for one fact-adjacent payload.
func stableID(factType string, identity map[string]any) string {
	return sdkidentity.StableID(factType, identity)
}
