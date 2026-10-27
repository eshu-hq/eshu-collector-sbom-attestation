// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"net/http"
	"strings"
	"time"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime/transport"
)

func defaultSourceHTTPClient(timeout time.Duration) *http.Client {
	return transport.DefaultHTTPClient(timeout)
}

func sourceHTTPTransportError(provider string, err error) error {
	return transport.HTTPError{
		Provider: strings.TrimSpace(provider),
		Message:  "request failed",
		Cause:    err,
	}
}

func sourceHTTPStatusError(provider string, statusCode int, header http.Header) error {
	return transport.HTTPError{
		Provider:        strings.TrimSpace(provider),
		StatusCode:      statusCode,
		Message:         http.StatusText(statusCode),
		RetryAfter:      transport.ParseRetryAfterHeader(header.Get("Retry-After")),
		RateLimitReason: strings.TrimSpace(header.Get("RateLimit-Reason")),
	}
}

func sourceHTTPDecodeError(provider string, err error) error {
	return transport.HTTPError{
		Provider: strings.TrimSpace(provider),
		Message:  "decode response",
		Cause:    err,
	}
}
