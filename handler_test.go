// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	factschemafixture "github.com/eshu-hq/eshu-sdk/factschema/fixturepack"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/document"
	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime"
)

func testClaim(scopeID string) sdk.Claim {
	return sdk.Claim{
		ComponentID:   "dev.eshu.collector.sbom-attestation",
		InstanceID:    "sbom-attestation-test",
		CollectorKind: runtime.CollectorKind,
		SourceSystem:  runtime.CollectorKind,
		Scope:         sdk.Scope{ID: scopeID, Kind: runtime.ScopeKind},
		GenerationID:  "sbom-attestation:gen-1",
		FencingToken:  "7",
		Deadline:      time.Now().Add(time.Hour),
	}
}

func testConfig(serverURL string) map[string]any {
	return map[string]any{
		"collector_instance_id": "sbom-attestation-test",
		"targets": []any{map[string]any{
			"scope_id":        "sbom://configured/example",
			"source_type":     "configured_source",
			"artifact_kind":   "sbom",
			"document_format": "cyclonedx",
			"document_url":    serverURL + "/sbom.json",
		}},
	}
}

func serveDocument(t *testing.T, status int, headers map[string]string, body []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, value := range headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func handleWithConfig(t *testing.T, serverURL string, claim sdk.Claim) (sdk.Result, string) {
	t.Helper()
	var log bytes.Buffer
	handler := Handler{Log: &log}
	result, err := handler.Handle(context.Background(), sdk.Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Config:          testConfig(serverURL),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	return result, log.String()
}

func TestHandleServesParsedDocumentAsComplete(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("document/testdata/cyclonedx_image_subject.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	server := serveDocument(t, http.StatusOK, nil, raw)
	claim := testClaim("sbom://configured/example")
	result, log := handleWithConfig(t, server.URL, claim)

	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete", result.State)
	}
	if len(result.Facts) == 0 {
		t.Fatal("complete result carries no facts")
	}
	if result.Claim != claim {
		t.Fatal("result does not echo the claim unchanged")
	}
	if result.Generation.ID != claim.GenerationID {
		t.Fatalf("Generation.ID = %q, want %q", result.Generation.ID, claim.GenerationID)
	}
	if len(result.Statuses) != 1 || result.Statuses[0].Class != sdk.StatusComplete {
		t.Fatalf("Statuses = %+v, want one complete row", result.Statuses)
	}
	if result.Statuses[0].FactCount != len(result.Facts) {
		t.Fatalf("FactCount = %d, want %d", result.Statuses[0].FactCount, len(result.Facts))
	}
	if !strings.Contains(log, `"event":"complete"`) {
		t.Fatalf("log = %q, want a complete diagnostic line", log)
	}

	schemas := map[string]json.RawMessage{}
	for _, kind := range document.SBOMAttestationFactKinds() {
		rawSchema, ok := factschemafixture.SchemaFor(kind)
		if !ok {
			t.Fatalf("pinned fixture pack ships no schema for %q", kind)
		}
		schemas[kind] = rawSchema
	}
	if err := conformance.ValidatePayloadSchemas(schemas, result); err != nil {
		t.Fatalf("ValidatePayloadSchemas() error = %v, want emitted payloads to satisfy published schemas", err)
	}
}

func TestHandleRejectsForeignCollectorKind(t *testing.T) {
	t.Parallel()

	handler := Handler{}
	claim := testClaim("sbom://configured/example")
	claim.CollectorKind = "sbom_document"
	_, err := handler.Handle(context.Background(), sdk.Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Config:          map[string]any{},
	})
	if err == nil || !strings.Contains(err.Error(), "claim.collector_kind") {
		t.Fatalf("Handle() error = %v, want collector-kind rejection", err)
	}
}

func TestHandleFailsTerminalOnInvalidConfig(t *testing.T) {
	t.Parallel()

	var log bytes.Buffer
	handler := Handler{Log: &log}
	claim := testClaim("sbom://configured/example")
	result, err := handler.Handle(context.Background(), sdk.Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Config:          map[string]any{},
	})
	if err != nil {
		t.Fatalf("Handle() error = %v, want a terminal result", err)
	}
	if result.State != sdk.ResultTerminal {
		t.Fatalf("State = %q, want terminal", result.State)
	}
	if len(result.Facts) != 0 {
		t.Fatalf("terminal result carries %d facts", len(result.Facts))
	}
	if got := result.Statuses[0].FailureClass; got != FailureInvalidConfig {
		t.Fatalf("FailureClass = %q, want %q", got, FailureInvalidConfig)
	}
	if !strings.Contains(log.String(), `"event":"config_failure"`) {
		t.Fatalf("log = %q, want a config_failure diagnostic line", log.String())
	}
}

func TestHandleRetriesUnknownScope(t *testing.T) {
	t.Parallel()

	server := serveDocument(t, http.StatusOK, nil, []byte(`{}`))
	claim := testClaim("sbom://configured/unconfigured")
	result, _ := handleWithConfig(t, server.URL, claim)

	if result.State != sdk.ResultRetryable {
		t.Fatalf("State = %q, want retryable", result.State)
	}
	if got := result.Statuses[0].FailureClass; got != FailureUnknownScope {
		t.Fatalf("FailureClass = %q, want %q", got, FailureUnknownScope)
	}
	if result.Statuses[0].RetryAfterSeconds != defaultRetryAfterSeconds {
		t.Fatalf("RetryAfterSeconds = %d, want %d", result.Statuses[0].RetryAfterSeconds, defaultRetryAfterSeconds)
	}
}

func TestHandleMapsProviderStatuses(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		status     int
		headers    map[string]string
		state      sdk.ResultState
		class      string
		retryAfter int
	}{
		"server error retries": {
			status: http.StatusBadGateway, state: sdk.ResultRetryable,
			class: ErrorClassRetryable, retryAfter: defaultRetryAfterSeconds,
		},
		"missing document is terminal": {
			status: http.StatusNotFound, state: sdk.ResultTerminal,
			class: ErrorClassNonRetryable,
		},
		"throttling retries with guidance": {
			status:  http.StatusTooManyRequests,
			headers: map[string]string{"Retry-After": "30"},
			state:   sdk.ResultRetryable, class: ErrorClassRateLimited, retryAfter: 30,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := serveDocument(t, test.status, test.headers, []byte(`{}`))
			claim := testClaim("sbom://configured/example")
			result, log := handleWithConfig(t, server.URL, claim)

			if result.State != test.state {
				t.Fatalf("State = %q, want %q", result.State, test.state)
			}
			if len(result.Facts) != 0 {
				t.Fatalf("failure result carries %d facts", len(result.Facts))
			}
			if got := result.Statuses[0].FailureClass; got != test.class {
				t.Fatalf("FailureClass = %q, want %q", got, test.class)
			}
			if got := result.Statuses[0].RetryAfterSeconds; got != test.retryAfter {
				t.Fatalf("RetryAfterSeconds = %d, want %d", got, test.retryAfter)
			}
			if !strings.Contains(log, `"event":"failure"`) {
				t.Fatalf("log = %q, want a failure diagnostic line", log)
			}
		})
	}
}
