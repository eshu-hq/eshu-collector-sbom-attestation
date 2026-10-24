// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
)

// This file is new in the extraction (no in-tree origin): it is the boundary
// where the collector-owned emission model meets the published SDK wire
// contract. Per SHIM_MAP section 2 (eshu-hq/eshu#8865), in-tree outcomes map
// to SDK ResultState as follows:
//
//   - envelopes committed -> "complete"
//   - hard error (fetch failure, invalid config, unparseable fencing token)
//     -> "terminal" caller error, never a silent zero
//   - cancellation -> no result
//
// There is deliberately no partial branch: this collector has no
// coverage-warning-to-partial signal (parser warnings are routine in-band
// sbom.warning facts, not partial states), so every committed snapshot is
// complete. A partial state would be dead code here.
//
// Dual collector-kind boundary: document-path envelopes stamp
// "sbom_document" and attestation-path envelopes stamp "sbom_attestation"
// (SHIM_MAP section 2). The SDK requires every fact's source system to equal
// the claim's, so the wire carries the claim-aligned system while the kinds
// stay distinct and the conformance manifest declares the per-kind family
// mapping. The envelope keeps its own CollectorKind untouched.

// SDKProtocolVersion is the collector extension wire contract this producer
// speaks (mirrors the SDK const so a bump is a deliberate edit).
const SDKProtocolVersion = sdkcollector.ProtocolVersionV1Alpha1

// ToSDKResult converts one collected snapshot into the SDK Result wire form
// for the given claim. The claim carries the core-owned work-item identity;
// the snapshot carries the observed evidence. FencingToken arrives on the
// claim as a string (SHIM_MAP section 6.7) and must round-trip exactly: a
// claim fencing token that is present but unparseable as an int64 is a
// terminal caller error, never a silent zero.
func ToSDKResult(claim sdkcollector.Claim, snap CollectedSnapshot) (sdkcollector.Result, error) {
	if strings.TrimSpace(string(claim.FencingToken)) != "" {
		if _, err := strconv.ParseInt(strings.TrimSpace(string(claim.FencingToken)), 10, 64); err != nil {
			return sdkcollector.Result{}, fmt.Errorf("claim fencing_token %q does not round-trip to int64: %w", claim.FencingToken, err)
		}
	}
	facts := make([]sdkcollector.Fact, 0, len(snap.Envelopes))
	for _, envelope := range snap.Envelopes {
		facts = append(facts, sdkFact(claim, envelope))
	}
	return sdkcollector.Result{
		ProtocolVersion: SDKProtocolVersion,
		State:           sdkcollector.ResultComplete,
		Claim:           claim,
		Generation: sdkcollector.Generation{
			ID:         snap.Generation.GenerationID,
			ObservedAt: snap.Generation.ObservedAt,
		},
		Facts: facts,
	}, nil
}

// ExhaustedResult builds the batch-drained result: complete with zero facts.
func ExhaustedResult(claim sdkcollector.Claim) sdkcollector.Result {
	return sdkcollector.Result{
		ProtocolVersion: SDKProtocolVersion,
		State:           sdkcollector.ResultComplete,
		Claim:           claim,
	}
}

func sdkFact(claim sdkcollector.Claim, envelope Envelope) sdkcollector.Fact {
	observedAt := envelope.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return sdkcollector.Fact{
		Kind:             envelope.FactKind,
		SchemaVersion:    envelope.SchemaVersion,
		StableKey:        envelope.StableFactKey,
		SourceConfidence: sdkcollector.SourceConfidence(envelope.SourceConfidence),
		ObservedAt:       observedAt,
		SourceRef: sdkcollector.SourceRef{
			SourceSystem: claim.SourceSystem,
			ScopeID:      envelope.SourceRef.ScopeID,
			GenerationID: envelope.SourceRef.GenerationID,
			FactKey:      envelope.SourceRef.FactKey,
			URI:          envelope.SourceRef.SourceURI,
			RecordID:     envelope.SourceRef.SourceRecordID,
		},
		Payload: envelope.Payload,
	}
}
