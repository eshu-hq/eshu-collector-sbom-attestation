// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/document"
)

// Parity case pins for #8865 (AC3, in-tree side). The plan, provider, and
// record/load helpers live in source_parity_8865_test.go; this file holds
// the Test functions so neither file breaches the 500-line cap.

// TestSBOM8865ParityLiveAgreesWithFixture is the AC3 source-parity pin:
// live collection and fixture agree per scope on IDs, kinds, stable keys,
// boundary attributes, and payload bytes.
func TestSBOM8865ParityLiveAgreesWithFixture(t *testing.T) {
	t.Parallel()

	if os.Getenv("UPDATE_8865_PARITY") != "" {
		plan := parity8865Plan(t)
		source := parity8865Source(t, plan)
		fixture := parity8865Fixture{}
		for _, c := range plan {
			fixture.Scopes = append(fixture.Scopes, parity8865Record(parity8865Collect(t, source, c)))
		}
		raw, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}
		if err := os.WriteFile(parity8865FixturePath, append(raw, '\n'), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		t.Logf("rewrote %s from live output; rerun without UPDATE_8865_PARITY=1", parity8865FixturePath)
		return
	}

	fixture := parity8865LoadFixture(t)
	plan := parity8865Plan(t)
	if len(fixture.Scopes) != len(plan) {
		t.Fatalf("fixture scopes = %d, want %d", len(fixture.Scopes), len(plan))
	}

	source := parity8865Source(t, plan)
	for i, c := range plan {
		expected := fixture.Scopes[i]
		if expected.ScopeID != c.target.ScopeID {
			t.Fatalf("fixture scope[%d] = %q, want %q", i, expected.ScopeID, c.target.ScopeID)
		}
		collected := parity8865Collect(t, source, c)
		if collected.Scope.ScopeID != expected.ScopeID {
			t.Fatalf("live ScopeID = %q, want %q", collected.Scope.ScopeID, expected.ScopeID)
		}
		if collected.Generation.GenerationID != expected.GenerationID {
			t.Fatalf("live GenerationID = %q, want %q", collected.Generation.GenerationID, expected.GenerationID)
		}
		envelopes := parity8865Drain(collected)
		if len(envelopes) != len(expected.Envelopes) {
			t.Fatalf("live envelopes = %d, want %d for scope %q", len(envelopes), len(expected.Envelopes), expected.ScopeID)
		}
		wantKinds := map[string]int{}
		wantKeys := make([]string, 0, len(expected.Envelopes))
		for _, recorded := range expected.Envelopes {
			wantKinds[recorded.FactKind]++
			wantKeys = append(wantKeys, recorded.StableKey)
		}
		slices.Sort(wantKeys)
		if got := parity8865KindMultiset(envelopes); !maps.Equal(got, wantKinds) {
			t.Fatalf("live kinds = %v, want %v for scope %q", got, wantKinds, expected.ScopeID)
		}
		if got := parity8865StableKeys(envelopes); !slices.Equal(got, wantKeys) {
			t.Fatalf("live stable keys differ from fixture for scope %q", expected.ScopeID)
		}
		for j, envelope := range envelopes {
			recorded := expected.Envelopes[j]
			wantAttr := strings.Join([]string{
				recorded.StableKey, recorded.FactKind, recorded.SchemaVersion,
				recorded.CollectorKind, recorded.SourceConfidence,
				recorded.SourceURI, recorded.SourceRecordID,
			}, "\x00")
			if got := parity8865AttrKey(envelope); got != wantAttr {
				t.Fatalf("live boundary attributes differ from fixture for scope %q key %q", expected.ScopeID, envelope.StableFactKey)
			}
			if envelope.FencingToken != parity8865FencingToken {
				t.Fatalf("FencingToken = %d, want %d", envelope.FencingToken, parity8865FencingToken)
			}
			if envelope.SchemaVersion != document.SBOMAttestationSchemaVersionV1 {
				t.Fatalf("SchemaVersion = %q, want %q for kind %q", envelope.SchemaVersion, document.SBOMAttestationSchemaVersionV1, envelope.FactKind)
			}
			if got, want := parity8865CanonicalJSON(t, envelope.Payload), parity8865CanonicalJSON(t, recorded.Payload); !bytes.Equal(got, want) {
				t.Fatalf("live payload bytes differ from fixture for scope %q kind %q key %q", expected.ScopeID, envelope.FactKind, envelope.StableFactKey)
			}
		}
	}

	union := map[string]bool{}
	for _, s := range fixture.Scopes {
		for _, envelope := range s.Envelopes {
			union[envelope.FactKind] = true
		}
	}
	for _, kind := range document.SBOMAttestationFactKinds() {
		if !union[kind] {
			t.Fatalf("fixture covers no %q fact; parity pack must span all 8 live kinds", kind)
		}
	}
}

// TestSBOM8865ParityDuplicateDeliveryIsStable pins duplicate safety: two
// identical claims per scope emit identical stable-key sets and payload
// bytes, so a redelivered generation commits idempotently at the core
// boundary. Every plan scope is pinned, since ROLLBACK_DRAFT.md step 5 cites
// this test for general redelivery safety.
func TestSBOM8865ParityDuplicateDeliveryIsStable(t *testing.T) {
	t.Parallel()

	plan := parity8865Plan(t)
	source := parity8865Source(t, plan)
	for _, c := range plan {
		first := parity8865Drain(parity8865Collect(t, source, c))
		second := parity8865Drain(parity8865Collect(t, source, c))
		if !slices.Equal(parity8865StableKeys(first), parity8865StableKeys(second)) {
			t.Fatalf("duplicate claims emit different stable keys for scope %q; redelivery would not be idempotent", c.target.ScopeID)
		}
		for i := range first {
			if got, want := parity8865CanonicalJSON(t, first[i].Payload), parity8865CanonicalJSON(t, second[i].Payload); !bytes.Equal(got, want) {
				t.Fatalf("duplicate claims emit different payload bytes for scope %q key %q", c.target.ScopeID, first[i].StableFactKey)
			}
		}
	}
}

// TestSBOM8865ParityHostileInputsPin pins the hostile half: malformed
// documents, credential redaction, blank statement status, no OCI facts on
// any scope, the record-ID channel, and the document/attestation
// collector-kind boundary.
func TestSBOM8865ParityHostileInputsPin(t *testing.T) {
	t.Parallel()

	plan := parity8865Plan(t)
	source := parity8865Source(t, plan)

	assertNoOCIReferrerFacts := func(scope string, envelopes []Envelope) {
		t.Helper()
		for i := range envelopes {
			// "oci_registry.image_referrer" is the registry lane's kind
			// (core-side); the runtime must never emit it.
			if envelopes[i].FactKind == "oci_registry.image_referrer" {
				t.Fatalf("runtime emitted OCI referrer fact %q in scope %s; OCI collector owns those facts", envelopes[i].FactID, scope)
			}
		}
	}

	malformed := parity8865Drain(parity8865Collect(t, source, plan[3]))
	var doc, warning *Envelope
	for i := range malformed {
		switch malformed[i].FactKind {
		case document.SBOMDocumentFactKind:
			doc = &malformed[i]
		case document.SBOMWarningFactKind:
			warning = &malformed[i]
		}
	}
	assertNoOCIReferrerFacts("malformed", malformed)
	if doc == nil {
		t.Fatal("malformed scope emitted no sbom.document envelope")
	}
	if warning == nil {
		t.Fatal("malformed scope emitted no sbom.warning envelope")
	}
	if got := payloadString(doc.Payload, "parse_status"); got != "malformed" {
		t.Fatalf("parse_status = %q, want malformed", got)
	}
	if got := payloadString(warning.Payload, "reason"); got != "malformed_document" {
		t.Fatalf("warning reason = %q, want malformed_document", got)
	}

	configured := parity8865Drain(parity8865Collect(t, source, plan[0]))
	assertNoOCIReferrerFacts("configured", configured)
	for _, envelope := range configured {
		for _, locator := range []string{envelope.SourceRef.SourceURI, payloadString(envelope.Payload, "source_uri")} {
			if strings.Contains(locator, "secret") || strings.Contains(locator, "token=") {
				t.Fatalf("source locator leaked sensitive material: %q", locator)
			}
		}
		if envelope.CollectorKind != "sbom_document" {
			t.Fatalf("document-path CollectorKind = %q, want sbom_document", envelope.CollectorKind)
		}
		// CUTOVER #4047, closed at extraction: the in-tree channel carries
		// the credential-bearing URL verbatim, but the extracted producer
		// refuses credential-bearing record IDs at the source (see
		// TestClaimedSourceRefusesCredentialBearingRecordID). No emitted
		// record ID may be a credential-bearing URL: per-fact composite
		// keys (digest:component:purl) are not URLs and skip the parse,
		// while anything hierarchical must carry no userinfo.
		recordID := envelope.SourceRef.SourceRecordID
		if parsed, err := url.Parse(recordID); err == nil && parsed.Host != "" && parsed.User != nil {
			t.Fatalf("SourceRecordID carries userinfo: %q", recordID)
		}
		if strings.Contains(recordID, "user:secret") || strings.Contains(recordID, "token=") {
			t.Fatalf("SourceRecordID carries the hostile credential markers: %q", recordID)
		}
	}

	referrer := parity8865Drain(parity8865Collect(t, source, plan[1]))
	assertNoOCIReferrerFacts("spdx-referrer", referrer)

	attested := parity8865Drain(parity8865Collect(t, source, plan[2]))
	assertNoOCIReferrerFacts("attested", attested)
	for _, envelope := range attested {
		if envelope.CollectorKind != string(CollectorKind) {
			t.Fatalf("attestation-path CollectorKind = %q, want %q", envelope.CollectorKind, CollectorKind)
		}
		if envelope.FactKind == document.AttestationStatementFactKind {
			if got := payloadString(envelope.Payload, "verification_status"); got != "" {
				t.Fatalf("statement verification_status = %q, want parser-owned blank status", got)
			}
		}
	}
}

// TestSBOM8865ParityInTreeEmissionCarriesEnforcementKeys pins the delegation
// delta's in-tree half: every emitted envelope carries a non-blank
// collector kind and the fencing token, the keys future grant enforcement
// will key on. Fail-closed behavior of the extracted producer is NOT pinned
// here (no grant mechanism exists in-tree); it is an open cutover item.
func TestSBOM8865ParityInTreeEmissionCarriesEnforcementKeys(t *testing.T) {
	t.Parallel()

	plan := parity8865Plan(t)
	source := parity8865Source(t, plan)
	for _, c := range plan {
		for _, envelope := range parity8865Drain(parity8865Collect(t, source, c)) {
			if envelope.CollectorKind == "" {
				t.Fatalf("CollectorKind is blank for kind %q; grant enforcement has nothing to key on", envelope.FactKind)
			}
			if envelope.FencingToken != parity8865FencingToken {
				t.Fatalf("FencingToken = %d, want %d", envelope.FencingToken, parity8865FencingToken)
			}
		}
	}
}
