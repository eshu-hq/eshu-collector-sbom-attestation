// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// TestServeOneClaimEndToEnd pipes one SDK request through the binary entry
// point over real HTTP: the document server answers, the handler collects,
// and stdout carries a complete result the host could commit.
func TestServeOneClaimEndToEnd(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "document", "testdata", "cyclonedx_image_subject.json"))
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(server.Close)

	request := map[string]any{
		"protocol_version": sdk.ProtocolVersionV1Alpha1,
		"claim": map[string]any{
			"component_id":   "dev.eshu.collector.sbom-attestation",
			"instance_id":    "sbom-attestation-test",
			"collector_kind": "sbom_attestation",
			"source_system":  "sbom_attestation",
			"scope":          map[string]any{"id": "sbom://configured/example", "kind": "sbom_attestation"},
			"source_run_id":  "run-e2e",
			"generation_id":  "sbom-attestation:gen-e2e",
			"work_item_id":   "work-e2e",
			"fencing_token":  "7",
			"attempt":        1,
			"deadline":       time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
			"config_handle":  "test-config",
		},
		"contract": map[string]any{"protocol_version": sdk.ProtocolVersionV1Alpha1},
		"config": map[string]any{
			"collector_instance_id": "sbom-attestation-test",
			"targets": []any{map[string]any{
				"scope_id":        "sbom://configured/example",
				"source_type":     "configured_source",
				"artifact_kind":   "sbom",
				"document_format": "cyclonedx",
				"document_url":    server.URL + "/sbom.json",
			}},
		},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), nil, bytes.NewReader(encoded), &stdout, &stderr, func(string) string { return "" }); err != nil {
		t.Fatalf("run() error = %v (stderr %q)", err, stderr.String())
	}
	var result sdk.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not a result: %v\n%s", err, stdout.String())
	}
	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete (stderr %q)", result.State, stderr.String())
	}
	if len(result.Facts) == 0 {
		t.Fatal("complete result carries no facts")
	}
	for _, fact := range result.Facts {
		if strings.TrimSpace(fact.Kind) == "" || strings.TrimSpace(fact.StableKey) == "" {
			t.Fatalf("fact carries no identity: %+v", fact)
		}
		if fact.SourceRef.SourceSystem != "sbom_attestation" {
			t.Fatalf("fact source system = %q, want the claim-aligned system", fact.SourceRef.SourceSystem)
		}
	}
}

// TestRunRejectsTrailingArgs proves an unexpected positional argument fails
// instead of being silently ignored.
func TestRunRejectsTrailingArgs(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"extra"}, &bytes.Buffer{}, &stdout, &stderr, nil); err == nil {
		t.Fatal("run() with a trailing argument error = nil")
	}
}
