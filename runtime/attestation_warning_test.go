// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/document"
)

// TestAttestationWarningEnvelopeMarksMalformed proves a statement that fails
// to parse still emits a warning envelope naming the statement and the parse
// failure, so operators see the malformed input instead of a silent drop.
func TestAttestationWarningEnvelopeMarksMalformed(t *testing.T) {
	t.Parallel()

	target := baseSLSATarget()
	item := workItem{
		ScopeID:             target.ScopeID,
		GenerationID:        "gen-warning",
		CollectorInstanceID: "sbom-attestation-test",
		CollectorKind:       CollectorKind,
		CurrentFencingToken: 7,
	}
	parseErr := errors.New("unexpected end of JSON input")
	warning := attestationWarningEnvelope(item, target, "statement-123", "https://example.com/stmt", "record-1", time.Now().UTC(), parseErr)

	if warning.FactKind != document.SBOMWarningFactKind {
		t.Errorf("warning.FactKind = %q, want %q", warning.FactKind, document.SBOMWarningFactKind)
	}
	if got := payloadString(warning.Payload, "reason"); got != "malformed_document" {
		t.Errorf("warning reason = %q, want malformed_document", got)
	}
	if got := payloadString(warning.Payload, "statement_id"); got != "statement-123" {
		t.Errorf("warning statement_id = %q, want statement-123", got)
	}
	if got := payloadString(warning.Payload, "summary"); !strings.Contains(got, parseErr.Error()) {
		t.Errorf("warning summary = %q, want the parse error quoted", got)
	}
}

// TestAttestationEnvelopesWarnOnMalformedInput proves the malformed branch of
// the envelope builder returns both the malformed statement envelope and the
// warning, through the same entry point production uses.
func TestAttestationEnvelopesWarnOnMalformedInput(t *testing.T) {
	t.Parallel()

	target := baseSLSATarget()
	item := workItem{ScopeID: target.ScopeID, GenerationID: "gen-malformed"}
	envs, err := attestationEnvelopes(item, target, []byte("{not json"), time.Now().UTC(), "https://example.com/stmt", "record-1")
	if err != nil {
		t.Fatalf("attestationEnvelopes() error = %v", err)
	}
	if len(envs) != 2 {
		t.Fatalf("attestationEnvelopes() returned %d envelopes, want 2 (statement + warning)", len(envs))
	}
	if envs[1].FactKind != document.SBOMWarningFactKind {
		t.Errorf("envs[1].FactKind = %q, want %q", envs[1].FactKind, document.SBOMWarningFactKind)
	}
}

// TestMergeContractPayloadNoErrorKeepsExisting proves a failing encode leaves
// the payload untouched and existing keys win over encoded ones.
func TestMergeContractPayloadNoErrorKeepsExisting(t *testing.T) {
	t.Parallel()

	payload := map[string]any{"keep": "original"}
	mergeContractPayloadNoError(payload, func() (map[string]any, error) {
		return nil, errors.New("contract encode failed")
	})
	if len(payload) != 1 || payload["keep"] != "original" {
		t.Errorf("payload after failed encode = %v, want untouched", payload)
	}

	mergeContractPayloadNoError(payload, func() (map[string]any, error) {
		return map[string]any{"keep": "overwrite", "fresh": "added"}, nil
	})
	if payload["keep"] != "original" || payload["fresh"] != "added" {
		t.Errorf("payload after merge = %v, want existing keys kept and fresh added", payload)
	}
}
