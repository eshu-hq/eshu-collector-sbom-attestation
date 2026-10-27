// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime"
	"github.com/eshu-hq/eshu-collector-sbom-attestation/runtime/transport"
)

// defaultRetryAfterSeconds bounds the host backoff when upstream gives no
// Retry-After guidance. The SDK requires a positive retry_after_seconds on
// retryable failure statuses, so a missing header cannot mean zero.
const defaultRetryAfterSeconds = 60

// Handler failure classes. They name the failure in operator status rows and
// never carry upstream bodies, URLs, or credentials.
const (
	// FailureInvalidConfig marks a claim whose activation config is missing
	// or malformed. It is terminal: retrying the same config cannot succeed.
	FailureInvalidConfig = "invalid_config"
	// FailureUnknownScope marks a claim scope no configured target covers.
	// It is retryable: the coordinator may configure it later, and a tight
	// terminal loop must not spin on it.
	FailureUnknownScope = "unknown_scope"
)

// Source error classes for collected failures.
const (
	// ErrorClassRateLimited marks provider throttling as retryable.
	ErrorClassRateLimited = "rate_limited"
	// ErrorClassRetryable marks transient failures as retryable.
	ErrorClassRetryable = "retryable"
	// ErrorClassNonRetryable marks malformed input or non-retryable
	// provider failures as terminal.
	ErrorClassNonRetryable = "non_retryable"
)

// Handler runs one SDK claim. The zero value is usable: it reads the process
// environment, the wall clock, and the real HTTPS document fetch path.
type Handler struct {
	// Getenv resolves credential environment variables; nil selects
	// os.Getenv, so the zero value reads the process environment.
	Getenv func(string) string
	// Now supplies the clock; nil selects time.Now.
	Now func() time.Time
	// Log receives one bounded JSON diagnostic line per claim; nil discards
	// it. The binary points it at stderr, which the extension host's process
	// runner does not surface (it keeps only a byte count), so the line
	// helps a local run and a test, not an operator in production.
	Log io.Writer
	// NewSource builds the claim-driven source; nil uses
	// runtime.NewClaimedSource with the standalone HTTP provider. Tests stub
	// it to inject a fake provider without HTTP.
	NewSource func(runtime.SourceConfig) (*runtime.ClaimedSource, error)
}

func (h Handler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h Handler) getenv(key string) string {
	if h.Getenv != nil {
		return h.Getenv(key)
	}
	return os.Getenv(key)
}

func (h Handler) newSource(config runtime.SourceConfig) (*runtime.ClaimedSource, error) {
	if config.Provider == nil {
		config.Provider = HTTPProvider{}
	}
	if h.NewSource != nil {
		return h.NewSource(config)
	}
	return runtime.NewClaimedSource(config)
}

// Handle collects the SBOM or attestation target named by the claim and
// returns the SDK result the host validates and commits. It never returns
// facts together with a failure state, never lets a credential into a
// result, and echoes the claim unchanged so the host's identity check
// passes.
func (h Handler) Handle(ctx context.Context, request sdk.Request) (sdk.Result, error) {
	started := h.now()
	claim := request.Claim
	if strings.TrimSpace(claim.CollectorKind) != runtime.CollectorKind {
		return sdk.Result{}, fmt.Errorf("claim.collector_kind %q is not %q", claim.CollectorKind, runtime.CollectorKind)
	}
	settings, err := ParseSettings(request.Config, h.getenv)
	if err != nil {
		// Parse errors name config keys only and never quote a configured
		// value, so they are safe for the diagnostic log line.
		h.logLine(map[string]any{
			"event": "config_failure", "scope": claim.Scope.ID,
			"generation": claim.GenerationID, "class": FailureInvalidConfig,
		})
		return terminalResult(claim, started, failureStatus(FailureInvalidConfig, 0, elapsedMS(started, h.now()))), nil
	}
	source, err := h.newSource(settings.Source)
	if err != nil {
		h.logLine(map[string]any{
			"event": "config_failure", "scope": claim.Scope.ID,
			"generation": claim.GenerationID, "class": FailureInvalidConfig,
		})
		return terminalResult(claim, started, failureStatus(FailureInvalidConfig, 0, elapsedMS(started, h.now()))), nil
	}
	snapshot, ok, err := source.NextClaimed(ctx, claim)
	if err != nil {
		return h.failureResult(claim, started, err), nil
	}
	if !ok {
		// NextClaimed reports every miss as an error; this is the late
		// safety net for a future false-without-error return.
		h.logLine(map[string]any{
			"event": "unknown_scope", "scope": claim.Scope.ID,
			"generation": claim.GenerationID, "class": FailureUnknownScope,
		})
		return retryableResult(claim, started, failureStatus(FailureUnknownScope, defaultRetryAfterSeconds, elapsedMS(started, h.now()))), nil
	}
	result, err := runtime.ToSDKResult(claim, snapshot)
	if err != nil {
		h.logLine(map[string]any{
			"event": "config_failure", "scope": claim.Scope.ID,
			"generation": claim.GenerationID, "class": FailureInvalidConfig,
		})
		return terminalResult(claim, started, failureStatus(FailureInvalidConfig, 0, elapsedMS(started, h.now()))), nil
	}
	latency := elapsedMS(started, h.now())
	h.logLine(map[string]any{
		"event": "complete", "scope": claim.Scope.ID,
		"generation": claim.GenerationID, "facts": len(result.Facts), "latency_ms": latency,
	})
	result.Statuses = append(result.Statuses, sdk.Status{
		Class:           sdk.StatusComplete,
		FactCount:       len(result.Facts),
		SourceLatencyMS: latency,
	})
	return result, nil
}

func (h Handler) failureResult(claim sdk.Claim, started time.Time, err error) sdk.Result {
	class, terminal, retryAfter := failureClass(err)
	latency := elapsedMS(started, h.now())
	h.logLine(map[string]any{
		"event": "failure", "scope": claim.Scope.ID,
		"generation": claim.GenerationID, "class": class,
		"http_status": responseStatusCode(err), "latency_ms": latency,
		"result": requestResult(err),
	})
	if terminal {
		return terminalResult(claim, started, failureStatus(class, 0, latency))
	}
	return retryableResult(claim, started, failureStatus(class, retryAfter, latency))
}

// failureClass maps a NextClaimed error onto a bounded failure class. An
// unconfigured scope stays retryable so the coordinator can add it later;
// provider HTTP statuses follow the sibling status mapping (429 and 5xx+
// retryable, other 4xx terminal); everything else is terminal
// invalid_config, because retrying the same claim against the same config
// cannot succeed (credential-bearing record, over-limit document,
// unparseable fencing token, unsupported artifact kind). Provider transport
// and decode failures arrive as status-less HTTPErrors and stay retryable.
func failureClass(err error) (class string, terminal bool, retryAfter int) {
	if strings.Contains(err.Error(), "is not configured for collector instance") {
		return FailureUnknownScope, false, defaultRetryAfterSeconds
	}
	var httpErr transport.HTTPError
	if errors.As(err, &httpErr) {
		retryAfter := defaultRetryAfterSeconds
		if httpErr.RetryAfterDelay() > 0 {
			if seconds := int(httpErr.RetryAfterDelay().Seconds()); seconds > 0 {
				retryAfter = seconds
			}
		}
		switch code := httpErr.StatusCode; {
		case code == http.StatusTooManyRequests:
			return ErrorClassRateLimited, false, retryAfter
		case code >= 400 && code < 500 && code != http.StatusRequestTimeout:
			return ErrorClassNonRetryable, true, 0
		default:
			return ErrorClassRetryable, false, retryAfter
		}
	}
	return FailureInvalidConfig, true, 0
}

// requestResult classifies a provider error for operator status rows. It is
// the sibling observe helper's shape: throttling stays distinct from
// terminal failure so the handler can choose retryable status.
func requestResult(err error) string {
	if err == nil {
		return "success"
	}
	var httpErr transport.HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusTooManyRequests {
		return "rate_limited"
	}
	return "error"
}

func responseStatusCode(err error) int {
	var httpErr transport.HTTPError
	if !errors.As(err, &httpErr) {
		return 0
	}
	return httpErr.StatusCode
}

func terminalResult(claim sdk.Claim, observedAt time.Time, status sdk.Status) sdk.Result {
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultTerminal,
		Claim:           claim,
		Generation: sdk.Generation{
			ID:         claim.GenerationID,
			ObservedAt: observedAt.UTC(),
		},
		Statuses: []sdk.Status{status},
	}
}

func retryableResult(claim sdk.Claim, observedAt time.Time, status sdk.Status) sdk.Result {
	return sdk.Result{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		State:           sdk.ResultRetryable,
		Claim:           claim,
		Generation: sdk.Generation{
			ID:         claim.GenerationID,
			ObservedAt: observedAt.UTC(),
		},
		Statuses: []sdk.Status{status},
	}
}

func failureStatus(class string, retryAfterSeconds, latencyMS int) sdk.Status {
	return sdk.Status{
		Class:             sdk.StatusFailure,
		FailureClass:      class,
		RetryAfterSeconds: retryAfterSeconds,
		SourceLatencyMS:   latencyMS,
	}
}

func elapsedMS(started, now time.Time) int {
	if now.Before(started) {
		return 0
	}
	return int(now.Sub(started).Milliseconds())
}

func (h Handler) logLine(fields map[string]any) {
	if h.Log == nil {
		return
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(h.Log, "%s\n", raw)
}
