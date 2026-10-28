// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package transport

import (
	"errors"
	"testing"
	"time"
)

// TestProviderFailureUnwrapExposesCause proves errors.As can reach the
// underlying provider error through the bounded failure wrapper.
func TestProviderFailureUnwrapExposesCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("dial tcp: connection refused")
	failure := NewProviderFailure("oci", FailureRetryable, false, cause)
	if got := failure.Unwrap(); got != cause {
		t.Errorf("Unwrap() = %v, want the cause", got)
	}
	httpCause := HTTPError{Provider: "oci", StatusCode: 500, Message: "boom"}
	wrapped := NewProviderFailure("oci", FailureRetryable, false, httpCause)
	if got := wrapped.Unwrap(); got != httpCause {
		t.Errorf("Unwrap() = %v, want the HTTP cause", got)
	}

	causeless := NewProviderFailure("oci", FailureRetryable, false, nil)
	if got := causeless.Unwrap(); got != nil {
		t.Errorf("Unwrap() without cause = %v, want nil", got)
	}
}

// TestDefaultHTTPClientBoundsTimeout proves an unset timeout falls back to
// the default while an explicit timeout is honored.
func TestDefaultHTTPClientBoundsTimeout(t *testing.T) {
	t.Parallel()

	if got := DefaultHTTPClient(0).Timeout; got != 30*time.Second {
		t.Errorf("DefaultHTTPClient(0).Timeout = %v, want the 30s default", got)
	}
	if got := DefaultHTTPClient(-time.Second).Timeout; got != 30*time.Second {
		t.Errorf("DefaultHTTPClient(negative).Timeout = %v, want the 30s default", got)
	}
	if got := DefaultHTTPClient(5 * time.Second).Timeout; got != 5*time.Second {
		t.Errorf("DefaultHTTPClient(5s).Timeout = %v, want 5s", got)
	}
}
