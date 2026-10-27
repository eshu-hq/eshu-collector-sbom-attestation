// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime"
)

func testTargetConfig() map[string]any {
	return map[string]any{
		"scope_id":        "sbom://configured/example",
		"source_type":     "configured_source",
		"artifact_kind":   "sbom",
		"document_format": "cyclonedx",
		"document_url":    "https://sbom.example.com/sbom.json",
	}
}

func parseOneTarget(t *testing.T, target map[string]any, getenv func(string) string) runtime.TargetConfig {
	t.Helper()
	settings, err := ParseSettings(map[string]any{
		"collector_instance_id": "sbom-attestation-test",
		"targets":               []any{target},
	}, getenv)
	if err != nil {
		t.Fatalf("ParseSettings() error = %v", err)
	}
	if len(settings.Source.Targets) != 1 {
		t.Fatalf("ParseSettings() targets = %d, want 1", len(settings.Source.Targets))
	}
	return settings.Source.Targets[0]
}

func TestParseSettingsRequiresCollectorInstanceID(t *testing.T) {
	t.Parallel()

	_, err := ParseSettings(map[string]any{}, nil)
	if err == nil || !strings.Contains(err.Error(), "collector_instance_id") {
		t.Fatalf("ParseSettings() error = %v, want collector_instance_id complaint", err)
	}
}

func TestParseSettingsRejectsNonListTargets(t *testing.T) {
	t.Parallel()

	_, err := ParseSettings(map[string]any{
		"collector_instance_id": "sbom-attestation-test",
		"targets":               "sbom://configured/example",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "targets must be a list") {
		t.Fatalf("ParseSettings() error = %v, want targets-must-be-a-list", err)
	}
}

func TestParseSettingsParsesConfiguredTarget(t *testing.T) {
	t.Parallel()

	target := parseOneTarget(t, testTargetConfig(), nil)
	if target.ScopeID != "sbom://configured/example" {
		t.Fatalf("ScopeID = %q", target.ScopeID)
	}
	if target.SourceType != runtime.SourceTypeConfigured {
		t.Fatalf("SourceType = %q", target.SourceType)
	}
	if target.ArtifactKind != runtime.ArtifactKindSBOM || target.DocumentFormat != runtime.DocumentFormatCycloneDX {
		t.Fatalf("ArtifactKind = %q DocumentFormat = %q", target.ArtifactKind, target.DocumentFormat)
	}
	if target.DocumentURL != "https://sbom.example.com/sbom.json" {
		t.Fatalf("DocumentURL = %q", target.DocumentURL)
	}
	if target.MaxBytes != 0 {
		t.Fatalf("MaxBytes = %d, want 0 (runtime default)", target.MaxBytes)
	}
}

func TestParseSettingsResolvesCredentialEnvReferences(t *testing.T) {
	t.Parallel()

	targetMap := testTargetConfig()
	targetMap["username_env"] = "SBOM_USER"
	targetMap["password_env"] = "SBOM_PASS"
	targetMap["bearer_token_env"] = "SBOM_TOKEN"
	getenv := func(key string) string {
		return map[string]string{
			"SBOM_USER":  "svc-user",
			"SBOM_PASS":  "svc-pass",
			"SBOM_TOKEN": "svc-token",
		}[key]
	}
	target := parseOneTarget(t, targetMap, getenv)
	if target.Username != "svc-user" || target.Password != "svc-pass" || target.BearerToken != "svc-token" {
		t.Fatalf("credentials = %q/%q/%q", target.Username, target.Password, target.BearerToken)
	}
}

func TestParseSettingsRejectsInlineCredentials(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"username", "password", "bearer_token"} {
		targetMap := testTargetConfig()
		targetMap[key] = "inline-secret"
		_, err := ParseSettings(map[string]any{
			"collector_instance_id": "sbom-attestation-test",
			"targets":               []any{targetMap},
		}, nil)
		if err == nil || !strings.Contains(err.Error(), key+"_env") {
			t.Fatalf("key %s: ParseSettings() error = %v, want *_env refusal", key, err)
		}
	}
}

func TestParseSettingsRejectsOCIReferrerTargets(t *testing.T) {
	t.Parallel()

	targetMap := testTargetConfig()
	targetMap["source_type"] = "oci_referrer"
	_, err := ParseSettings(map[string]any{
		"collector_instance_id": "sbom-attestation-test",
		"targets":               []any{targetMap},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "oci_referrer") {
		t.Fatalf("ParseSettings() error = %v, want oci_referrer refusal", err)
	}
}

func TestParseSettingsRejectsUnknownSourceType(t *testing.T) {
	t.Parallel()

	targetMap := testTargetConfig()
	delete(targetMap, "source_type")
	_, err := ParseSettings(map[string]any{
		"collector_instance_id": "sbom-attestation-test",
		"targets":               []any{targetMap},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "source_type") {
		t.Fatalf("ParseSettings() error = %v, want source_type complaint", err)
	}
}

func TestParseSettingsParsesMaxBytesShapes(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]any{
		"json number": json.Number("1048576"),
		"float64":     float64(1048576),
		"int":         int(1048576),
		"int64":       int64(1048576),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			targetMap := testTargetConfig()
			targetMap["max_bytes"] = value
			target := parseOneTarget(t, targetMap, nil)
			if target.MaxBytes != 1048576 {
				t.Fatalf("MaxBytes = %d, want 1048576", target.MaxBytes)
			}
		})
	}
}

func TestParseSettingsRejectsNonIntegerMaxBytes(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]any{
		"string":   "1048576",
		"fraction": float64(1.5),
		"bad json": json.Number("many"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			targetMap := testTargetConfig()
			targetMap["max_bytes"] = value
			_, err := ParseSettings(map[string]any{
				"collector_instance_id": "sbom-attestation-test",
				"targets":               []any{targetMap},
			}, nil)
			if err == nil || !strings.Contains(err.Error(), "max_bytes") {
				t.Fatalf("ParseSettings() error = %v, want max_bytes complaint", err)
			}
		})
	}
}

func TestParseSettingsRejectsNonStringValues(t *testing.T) {
	t.Parallel()

	targetMap := testTargetConfig()
	targetMap["scope_id"] = 42
	_, err := ParseSettings(map[string]any{
		"collector_instance_id": "sbom-attestation-test",
		"targets":               []any{targetMap},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "scope_id") {
		t.Fatalf("ParseSettings() error = %v, want scope_id complaint", err)
	}
}
