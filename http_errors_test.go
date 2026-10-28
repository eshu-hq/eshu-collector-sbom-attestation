// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"errors"
	"testing"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime/transport"
)

// TestSourceHTTPErrorsShape proves the transport and decode error constructors
// carry the provider, a bounded message, and the cause for retry decisions.
func TestSourceHTTPErrorsShape(t *testing.T) {
	t.Parallel()

	cause := errors.New("dial tcp: connection refused")
	transportErr, ok := sourceHTTPTransportError(" oci ", cause).(transport.HTTPError)
	if !ok {
		t.Fatalf("sourceHTTPTransportError() type = %T, want transport.HTTPError", transportErr)
	}
	if transportErr.Provider != "oci" || transportErr.Message != "request failed" || transportErr.Cause != cause {
		t.Errorf("sourceHTTPTransportError() = %+v, want trimmed provider with cause", transportErr)
	}

	decodeErr, ok := sourceHTTPDecodeError("oci", cause).(transport.HTTPError)
	if !ok {
		t.Fatalf("sourceHTTPDecodeError() type = %T, want transport.HTTPError", decodeErr)
	}
	if decodeErr.Message != "decode response" || decodeErr.Cause != cause {
		t.Errorf("sourceHTTPDecodeError() = %+v, want decode message with cause", decodeErr)
	}
}

// TestHandlerGetenvFallsBackToProcess proves a handler without a Getenv hook
// reads the process environment, so the zero value stays usable.
func TestHandlerGetenvFallsBackToProcess(t *testing.T) {
	t.Setenv("ESHU_SBOM_ATTESTATION_TEST_GETENV", "from-process")

	var h Handler
	if got := h.getenv("ESHU_SBOM_ATTESTATION_TEST_GETENV"); got != "from-process" {
		t.Errorf("Handler{}.getenv() = %q, want process value", got)
	}
	hooked := Handler{Getenv: func(string) string { return "from-hook" }}
	if got := hooked.getenv("ESHU_SBOM_ATTESTATION_TEST_GETENV"); got != "from-hook" {
		t.Errorf("Handler{Getenv}.getenv() = %q, want hook value", got)
	}
}

// TestHasInlineValueShapes proves blank and absent values pass while any real
// inline credential — string or mistyped — is reported for rejection.
func TestHasInlineValueShapes(t *testing.T) {
	t.Parallel()

	for value, want := range map[any]bool{
		nil: false, "": false, "   ": false,
		"secret": true, 0: true, 42: true, true: true,
	} {
		if got := hasInlineValue(value); got != want {
			t.Errorf("hasInlineValue(%#v) = %v, want %v", value, got, want)
		}
	}
}
