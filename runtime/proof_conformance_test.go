// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/document"
)

// This file is new in the extraction: it is the #4047 cutover gate's
// extracted-path half for eshu-hq/eshu#8865. It proves the SDK wire
// conversion and that every emitted fact payload satisfies the pinned
// fixture-pack schemas.

// proofStampKind returns the collector kind stamped on envelopes of one fact
// kind: document-path facts carry "sbom_document", attestation-path facts
// carry "sbom_attestation" (SHIM_MAP section 2).
func proofStampKind(kind string) string {
	switch kind {
	case document.SBOMDocumentFactKind,
		document.SBOMComponentFactKind,
		document.SBOMDependencyRelationshipFactKind,
		document.SBOMExternalReferenceFactKind,
		document.SBOMWarningFactKind:
		return document.CollectorKind
	default:
		return CollectorKind
	}
}

// proofManifest declares this producer's emitted families for the conformance
// harness: the 8 sbom.*/attestation.* kinds at 1.1.0, all reported
// confidence, trusted to this producer's two collector kinds.
func proofManifest() conformance.Manifest {
	families := []conformance.FactFamily{
		{Kind: document.SBOMDocumentFactKind, SchemaVersions: []string{document.SBOMAttestationSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: document.SBOMComponentFactKind, SchemaVersions: []string{document.SBOMAttestationSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: document.SBOMDependencyRelationshipFactKind, SchemaVersions: []string{document.SBOMAttestationSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: document.SBOMExternalReferenceFactKind, SchemaVersions: []string{document.SBOMAttestationSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: document.AttestationStatementFactKind, SchemaVersions: []string{document.SBOMAttestationSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: document.AttestationSLSAProvenanceFactKind, SchemaVersions: []string{document.SBOMAttestationSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: document.AttestationSignatureVerificationFactKind, SchemaVersions: []string{document.SBOMAttestationSchemaVersionV1}, SourceConfidence: []string{"reported"}},
		{Kind: document.SBOMWarningFactKind, SchemaVersions: []string{document.SBOMAttestationSchemaVersionV1}, SourceConfidence: []string{"reported"}},
	}
	return conformance.Manifest{
		APIVersion: "eshu.dev/v1alpha1",
		Kind:       "ComponentPackage",
		Metadata: conformance.Metadata{
			ID:        "dev.eshu.collector.sbom-attestation",
			Name:      "SBOM attestation collector",
			Publisher: "eshu-hq",
			Version:   "0.1.0",
		},
		Spec: conformance.Spec{
			CompatibleCore: ">=0.0.5 <0.2.0",
			ComponentType:  "collector",
			CollectorKinds: []string{document.CollectorKind, CollectorKind},
			Runtime: conformance.RuntimeContract{
				SDKProtocol: sdkcollector.ProtocolVersionV1Alpha1,
				Adapter:     "process",
			},
			EmittedFacts: families,
		},
	}
}

func proofCoreFacts(t *testing.T, manifest conformance.Manifest) (*conformance.CoreFactContext, map[string]json.RawMessage) {
	t.Helper()

	authorizations := []conformance.CoreFactAuthorization{}
	schemas := map[string]json.RawMessage{}
	for _, family := range manifest.Spec.EmittedFacts {
		schema, ok := fixturepack.SchemaFor(family.Kind)
		if !ok {
			t.Fatalf("pinned fixture pack ships no schema for %q", family.Kind)
		}
		schemas[family.Kind] = schema
		emissions := []conformance.CoreFactEmission{{CollectorKind: proofStampKind(family.Kind), SchemaVersions: family.SchemaVersions}}
		authorizations = append(authorizations, conformance.CoreFactAuthorization{
			Kind:             family.Kind,
			Emissions:        emissions,
			ReducerPhases:    []string{conformance.SourceEvidenceOnlyReducerPhase},
			PayloadSchemaRef: family.Kind,
		})
	}
	return &conformance.CoreFactContext{
		ComponentID:      manifest.Metadata.ID,
		ComponentVersion: manifest.Metadata.Version,
		Facts:            authorizations,
	}, schemas
}

// proofClaim builds the core-owned work-item identity for one collected
// snapshot, mirroring what the host passes at cutover.
func proofClaim(collected CollectedSnapshot, fencingToken int64) sdkcollector.Claim {
	observedAt := collected.Generation.ObservedAt
	return sdkcollector.Claim{
		ComponentID:   "dev.eshu.collector.sbom-attestation",
		InstanceID:    parity8865InstanceID,
		CollectorKind: CollectorKind,
		SourceSystem:  CollectorKind,
		Scope:         sdkcollector.Scope{ID: collected.Scope.ScopeID, Kind: collected.Scope.ScopeKind},
		SourceRunID:   "run-proof-8865",
		GenerationID:  collected.Generation.GenerationID,
		WorkItemID:    "work-proof-8865",
		FencingToken:  strconv.FormatInt(fencingToken, 10),
		Attempt:       1,
		Deadline:      observedAt.Add(time.Hour),
		ConfigHandle:  "proof-config:sbom-attestation",
	}
}

func proofSnapshots(t *testing.T) []sdkcollector.Result {
	t.Helper()

	plan := parity8865Plan(t)
	source := parity8865Source(t, plan)
	var fixtures []sdkcollector.Result
	for _, c := range plan {
		collected := parity8865Collect(t, source, c)
		claim := proofClaim(collected, parity8865FencingToken)
		result, err := ToSDKResult(claim, collected)
		if err != nil {
			t.Fatalf("ToSDKResult() error = %v", err)
		}
		fixtures = append(fixtures, result)
	}
	if len(fixtures) != len(plan) {
		t.Fatalf("fixtures = %d, want %d plan cases", len(fixtures), len(plan))
	}
	return fixtures
}

// TestExtractedSDKResultBoundary proves the SDK wire conversion: complete
// state, 1:1 envelope mapping with identity and source ref preserved
// (source system claim-aligned per the published contract), fencing
// round-trip failure closed, and exhaustion yielding a fact-free complete.
func TestExtractedSDKResultBoundary(t *testing.T) {
	t.Parallel()

	plan := parity8865Plan(t)
	source := parity8865Source(t, plan)
	collected := parity8865Collect(t, source, plan[0])
	claim := proofClaim(collected, parity8865FencingToken)
	result, err := ToSDKResult(claim, collected)
	if err != nil {
		t.Fatalf("ToSDKResult() error = %v", err)
	}
	if result.ProtocolVersion != sdkcollector.ProtocolVersionV1Alpha1 {
		t.Fatalf("ProtocolVersion = %q, want v1alpha1", result.ProtocolVersion)
	}
	if result.State != sdkcollector.ResultComplete {
		t.Fatalf("State = %q, want complete", result.State)
	}
	if len(result.Facts) != len(collected.Envelopes) {
		t.Fatalf("Facts = %d, want %d (1:1 envelope mapping)", len(result.Facts), len(collected.Envelopes))
	}
	for i, fact := range result.Facts {
		envelope := collected.Envelopes[i]
		if fact.Kind != envelope.FactKind || fact.StableKey != envelope.StableFactKey ||
			fact.SchemaVersion != envelope.SchemaVersion {
			t.Fatalf("fact[%d] identity mismatch: %v/%v/%v", i, fact.Kind, fact.StableKey, fact.SchemaVersion)
		}
		if fact.SourceRef.SourceSystem != claim.SourceSystem ||
			fact.SourceRef.ScopeID != envelope.SourceRef.ScopeID ||
			fact.SourceRef.GenerationID != envelope.SourceRef.GenerationID ||
			fact.SourceRef.FactKey != envelope.SourceRef.FactKey ||
			fact.SourceRef.URI != envelope.SourceRef.SourceURI ||
			fact.SourceRef.RecordID != envelope.SourceRef.SourceRecordID {
			t.Fatalf("fact[%d] source ref not preserved: %#v", i, fact.SourceRef)
		}
		if string(fact.SourceConfidence) != document.SourceConfidenceReported {
			t.Fatalf("fact[%d] confidence = %q, want reported", i, fact.SourceConfidence)
		}
	}

	bad := proofClaim(collected, parity8865FencingToken)
	bad.FencingToken = "not-an-int"
	if _, err := ToSDKResult(bad, collected); err == nil {
		t.Fatal("ToSDKResult with unparseable fencing token succeeded, want terminal caller error")
	}

	exhausted := ExhaustedResult(claim)
	if exhausted.State != sdkcollector.ResultComplete || len(exhausted.Facts) != 0 {
		t.Fatalf("ExhaustedResult = %#v, want complete with zero facts", exhausted)
	}
}

// TestExtractedPayloadsPassConformance proves every emitted fact payload
// satisfies the JSON Schema shapes the pinned fixture pack ships, via the
// schema-only check.
func TestExtractedPayloadsPassConformance(t *testing.T) {
	t.Parallel()

	manifest := proofManifest()
	_, schemas := proofCoreFacts(t, manifest)
	for i, fixture := range proofSnapshots(t) {
		if err := conformance.ValidatePayloadSchemas(schemas, fixture); err != nil {
			t.Fatalf("fixture[%d] payload schema: %v", i, err)
		}
		if len(fixture.Facts) == 0 {
			t.Fatalf("fixture[%d] has no facts, want every emitted fact validated", i)
		}
	}
}
