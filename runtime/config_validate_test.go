// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"strings"
	"testing"
)

// validConfiguredTarget returns a target that passes validation, so each
// failure case below breaks exactly one rule.
func validConfiguredTarget() TargetConfig {
	return TargetConfig{
		ScopeID:        "sbom://configured/example",
		SourceType:     SourceTypeConfigured,
		ArtifactKind:   ArtifactKindSBOM,
		DocumentFormat: DocumentFormatCycloneDX,
		DocumentURL:    "https://example.com/sbom.json",
	}
}

// TestTargetValidateFailsClosed proves every required target field is
// enforced: a missing or mistyped field rejects the target with a named
// error instead of fetching from a guessed source.
func TestTargetValidateFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(*TargetConfig)
		want   string
	}{
		{"scope required", func(t *TargetConfig) { t.ScopeID = "  " }, "scope_id is required"},
		{"artifact kind required", func(t *TargetConfig) { t.ArtifactKind = "" }, "artifact_kind is required"},
		{"artifact kind unknown", func(t *TargetConfig) { t.ArtifactKind = "nope" }, "unsupported artifact_kind"},
		{"format required", func(t *TargetConfig) { t.DocumentFormat = "" }, "document_format is required"},
		{"format unknown", func(t *TargetConfig) { t.DocumentFormat = "nope" }, "unsupported document_format"},
		{"cyclonedx needs sbom kind", func(t *TargetConfig) {
			t.ArtifactKind = ArtifactKindAttestation
			t.DocumentFormat = DocumentFormatSPDX
		}, "only valid for SBOM targets"},
		{"intoto needs attestation kind", func(t *TargetConfig) {
			t.DocumentFormat = DocumentFormatInToto
		}, "only valid for attestation targets"},
		{"configured needs url", func(t *TargetConfig) { t.DocumentURL = "" }, "document_url is required"},
		{"source type unknown", func(t *TargetConfig) { t.SourceType = "nope" }, "unsupported source_type"},
		{"negative max bytes", func(t *TargetConfig) { t.MaxBytes = -1 }, "max_bytes must not be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			target := validConfiguredTarget()
			tc.mutate(&target)
			if _, err := target.validate(); err == nil {
				t.Fatal("validate() error = nil, want failure")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validate() error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

// TestTargetValidateOCIRequiresFields proves each OCI referrer field is
// enforced independently, so a half-configured referrer cannot fetch.
func TestTargetValidateOCIRequiresFields(t *testing.T) {
	t.Parallel()

	base := TargetConfig{
		ScopeID:        "sbom://attestation/slsa",
		SourceType:     SourceTypeOCIReferrer,
		ArtifactKind:   ArtifactKindAttestation,
		DocumentFormat: DocumentFormatInToto,
		Provider:       "oci",
		Registry:       "https://registry.example.com",
		Repository:     "library/example",
		SubjectDigest:  "sha256:1111",
		ReferrerDigest: "sha256:2222",
	}
	for field, blank := range map[string]func(*TargetConfig){
		"provider":        func(t *TargetConfig) { t.Provider = "" },
		"registry":        func(t *TargetConfig) { t.Registry = "" },
		"repository":      func(t *TargetConfig) { t.Repository = "" },
		"subject_digest":  func(t *TargetConfig) { t.SubjectDigest = "" },
		"referrer_digest": func(t *TargetConfig) { t.ReferrerDigest = "" },
	} {
		target := base
		blank(&target)
		if _, err := target.validate(); err == nil {
			t.Errorf("validate() without %s error = nil, want failure", field)
		} else if !strings.Contains(err.Error(), field) {
			t.Errorf("validate() without %s error = %q, want the field named", field, err)
		}
	}
}

// TestTargetValidateAppliesDefaults proves validation fills the byte budget
// and derives the source URI and record ID, keeping explicit values intact.
func TestTargetValidateAppliesDefaults(t *testing.T) {
	t.Parallel()

	target := validConfiguredTarget()
	got, err := target.validate()
	if err != nil {
		t.Fatalf("validate() error = %v", err)
	}
	if got.MaxBytes != defaultMaxDocumentBytes {
		t.Errorf("MaxBytes = %d, want default %d", got.MaxBytes, defaultMaxDocumentBytes)
	}
	if got.SourceURI != "https://example.com/sbom.json" {
		t.Errorf("SourceURI = %q, want the document URL", got.SourceURI)
	}
	// Derivation order is referrer digest, document URL, then scope: the
	// configured URL wins here because no referrer digest is set.
	if got.SourceRecordID != "https://example.com/sbom.json" {
		t.Errorf("SourceRecordID = %q, want the document URL fallback", got.SourceRecordID)
	}

	explicit := validConfiguredTarget()
	explicit.SourceURI = "https://example.com/explicit"
	explicit.SourceRecordID = "record-9"
	explicit.MaxBytes = 1024
	got, err = explicit.validate()
	if err != nil {
		t.Fatalf("validate() error = %v", err)
	}
	if got.SourceURI != explicit.SourceURI || got.SourceRecordID != explicit.SourceRecordID || got.MaxBytes != 1024 {
		t.Errorf("validate() rewrote explicit fields: %+v", got)
	}
}
