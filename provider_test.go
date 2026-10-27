// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime"
	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime/transport"
)

func configuredTarget(scopeID, documentURL string) runtime.TargetConfig {
	return runtime.TargetConfig{
		ScopeID:        scopeID,
		SourceType:     runtime.SourceTypeConfigured,
		ArtifactKind:   runtime.ArtifactKindSBOM,
		DocumentFormat: runtime.DocumentFormatCycloneDX,
		DocumentURL:    documentURL,
	}
}

func TestFetchDocumentSendsAuthAndBoundsMetadata(t *testing.T) {
	t.Parallel()

	var gotAccept, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	provider := HTTPProvider{Now: func() time.Time { return now }}
	target := configuredTarget("sbom://configured/example", server.URL+"/sbom.json")
	target.BearerToken = "svc-token"
	document, err := provider.FetchDocument(context.Background(), target)
	if err != nil {
		t.Fatalf("FetchDocument() error = %v", err)
	}
	if string(document.Body) != `{}` {
		t.Fatalf("Body = %q", document.Body)
	}
	if document.SourceURI != server.URL+"/sbom.json" {
		t.Fatalf("SourceURI = %q", document.SourceURI)
	}
	if document.MediaType != "application/json; charset=utf-8" {
		t.Fatalf("MediaType = %q", document.MediaType)
	}
	if !document.ObservedAt.Equal(now) {
		t.Fatalf("ObservedAt = %v, want %v", document.ObservedAt, now)
	}
	if gotAccept != "application/json" {
		t.Fatalf("Accept = %q", gotAccept)
	}
	if gotAuth != "Bearer svc-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}

func TestFetchDocumentSendsBasicAuth(t *testing.T) {
	t.Parallel()

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	target := configuredTarget("sbom://configured/example", server.URL)
	target.Username = "svc-user"
	target.Password = "svc-pass"
	provider := HTTPProvider{}
	if _, err := provider.FetchDocument(context.Background(), target); err != nil {
		t.Fatalf("FetchDocument() error = %v", err)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("Authorization = %q, want Basic", gotAuth)
	}
}

func TestFetchDocumentRejectsCredentialBearingURL(t *testing.T) {
	t.Parallel()

	target := configuredTarget("sbom://configured/example", "https://user:secret@sbom.example.com/sbom.json")
	_, err := HTTPProvider{}.FetchDocument(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("FetchDocument() error = %v, want credential refusal", err)
	}
}

func TestFetchDocumentRejectsOCIReferrer(t *testing.T) {
	t.Parallel()

	target := configuredTarget("sbom://configured/example", "https://sbom.example.com/sbom.json")
	target.SourceType = runtime.SourceTypeOCIReferrer
	_, err := HTTPProvider{}.FetchDocument(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "configured_source only") {
		t.Fatalf("FetchDocument() error = %v, want configured_source-only refusal", err)
	}
}

func TestFetchDocumentMapsHTTPStatuses(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/throttled":
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	_, err := HTTPProvider{}.FetchDocument(context.Background(), configuredTarget("sbom://configured/a", server.URL+"/throttled"))
	if err == nil {
		t.Fatal("FetchDocument() error = nil, want throttling")
	}
	var httpErr transport.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("FetchDocument() error = %v, want status 429", err)
	}
	if got := httpErr.RetryAfterDelay(); got != 30*time.Second {
		t.Fatalf("RetryAfterDelay() = %v, want 30s", got)
	}

	_, err = HTTPProvider{}.FetchDocument(context.Background(), configuredTarget("sbom://configured/b", server.URL+"/missing"))
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
		t.Fatalf("FetchDocument() error = %v, want status 404", err)
	}
}

func TestFetchDocumentKeepsOverLimitBodyForTheChokePoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"too":"big-for-sixteen-bytes"}`))
	}))
	t.Cleanup(server.Close)

	target := configuredTarget("sbom://configured/example", server.URL)
	target.MaxBytes = 16
	document, err := HTTPProvider{}.FetchDocument(context.Background(), target)
	if err != nil {
		t.Fatalf("FetchDocument() error = %v, want the over-long body returned for the choke point", err)
	}
	if int64(len(document.Body)) <= target.MaxBytes {
		t.Fatalf("len(Body) = %d, want over the 16-byte bound", len(document.Body))
	}
}

func TestFetchDocumentTruncatesLongMediaTypes(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json"+strings.Repeat("; x=y", 64))
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	document, err := HTTPProvider{}.FetchDocument(context.Background(), configuredTarget("sbom://configured/example", server.URL))
	if err != nil {
		t.Fatalf("FetchDocument() error = %v", err)
	}
	if len(document.MediaType) != maxMediaTypeLength {
		t.Fatalf("len(MediaType) = %d, want %d", len(document.MediaType), maxMediaTypeLength)
	}
}

func TestFetchDocumentRequiresURL(t *testing.T) {
	t.Parallel()

	_, err := HTTPProvider{}.FetchDocument(context.Background(), configuredTarget("sbom://configured/example", ""))
	if err == nil {
		t.Fatal("FetchDocument() error = nil, want document_url complaint")
	}
}
