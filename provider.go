// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime"
	"github.com/eshu-hq/eshu-collector-sbom-attestation/urlredact"
)

const defaultFetchTimeout = 30 * time.Second

// maxMediaTypeLength caps the Content-Type recorded on a fetched document.
// The value is operator-visible metadata, never a fact, and an unbounded
// header must not flow into the snapshot.
const maxMediaTypeLength = 128

// HTTPProvider fetches explicitly configured SBOM and attestation documents
// over HTTPS. It implements runtime.DocumentProvider for the standalone
// image, which serves configured_source targets only: oci_referrer discovery
// stays core-side, and ParseSettings already rejects it at admission, so the
// default branch here is an unreachable safety net, never a silent skip.
type HTTPProvider struct {
	HTTPClient *http.Client
	Now        func() time.Time
}

// FetchDocument fetches one configured document URL with the target's
// credentials on the Authorization header. The body is read bounded by the
// target's MaxBytes (plus one probe byte): an over-limit body is returned
// over-long so the runtime choke point fails closed with its standard
// max_bytes error instead of this path truncating evidence silently.
func (p HTTPProvider) FetchDocument(ctx context.Context, target runtime.TargetConfig) (runtime.Document, error) {
	switch target.SourceType {
	case runtime.SourceTypeConfigured:
		return p.fetchURL(ctx, target, target.DocumentURL)
	default:
		return runtime.Document{}, fmt.Errorf("standalone image does not serve source_type %q (configured_source only)", target.SourceType)
	}
}

func (p HTTPProvider) fetchURL(ctx context.Context, target runtime.TargetConfig, rawURL string) (runtime.Document, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return runtime.Document{}, fmt.Errorf("document_url is required")
	}
	if urlredact.CarriesUserinfo(trimmed) {
		return runtime.Document{}, fmt.Errorf("document_url carries a credential: configure an explicit source_record_id and carry credentials by *_env reference")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, trimmed, nil)
	if err != nil {
		return runtime.Document{}, sourceHTTPTransportError("sbom_attestation", err)
	}
	request.Header.Set("Accept", "application/json")
	if target.Username != "" || target.Password != "" {
		request.SetBasicAuth(target.Username, target.Password)
	}
	if target.BearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+target.BearerToken)
	}
	response, err := p.client().Do(request)
	if err != nil {
		return runtime.Document{}, sourceHTTPTransportError("sbom_attestation", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return runtime.Document{}, sourceHTTPStatusError("sbom_attestation", response.StatusCode, response.Header)
	}
	limit := target.MaxBytes
	if limit <= 0 {
		limit = 10 * 1024 * 1024
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return runtime.Document{}, sourceHTTPDecodeError("sbom_attestation", err)
	}
	observedAt := time.Now().UTC()
	if p.Now != nil {
		observedAt = p.Now().UTC()
	}
	return runtime.Document{
		Body:           body,
		SourceURI:      trimmed,
		SourceRecordID: "",
		MediaType:      boundedMediaType(response.Header.Get("Content-Type")),
		ObservedAt:     observedAt,
	}, nil
}

func (p HTTPProvider) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return defaultSourceHTTPClient(defaultFetchTimeout)
}

func boundedMediaType(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) > maxMediaTypeLength {
		trimmed = trimmed[:maxMediaTypeLength]
	}
	return trimmed
}
