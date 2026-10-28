// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package urlredact

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// TestAuthorityKeepsPlainURLsUnrewritten pins the common path: a
// hierarchical URL parses directly with no authority rewrite.
func TestAuthorityKeepsPlainURLsUnrewritten(t *testing.T) {
	t.Parallel()

	parsed, rewritten, err := Authority("https://sbom.example.com/private/sbom.json")
	if err != nil {
		t.Fatalf("Authority() error = %v", err)
	}
	if rewritten {
		t.Fatal("Authority() rewritten = true, want false for a hierarchical URL")
	}
	if parsed.User != nil {
		t.Fatalf("Authority().User = %v, want nil", parsed.User)
	}
	if got := parsed.Host; got != "sbom.example.com" {
		t.Fatalf("Authority().Host = %q, want %q", got, "sbom.example.com")
	}
}

// TestAuthorityRewritesOpaqueCredentials pins the reason this package
// exists: net/url reads no userinfo without "//", so an opaque
// credential-shaped body is re-parsed as an authority and the credential
// becomes visible to the caller.
func TestAuthorityRewritesOpaqueCredentials(t *testing.T) {
	t.Parallel()

	parsed, rewritten, err := Authority("svc:PASSWORD@h.internal:5432/tool")
	if err != nil {
		t.Fatalf("Authority() error = %v", err)
	}
	if !rewritten {
		t.Fatal("Authority() rewritten = false, want true for an opaque authority")
	}
	if parsed.User == nil {
		t.Fatal("Authority().User = nil, want the re-parsed userinfo")
	}
}

// TestAuthorityLeavesPurlsAndPathsAlone pins the rewrite guard: an "@"
// after the first "/" is a version separator, not a userinfo boundary,
// and a bare tool path carries no authority at all.
func TestAuthorityLeavesPurlsAndPathsAlone(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"pkg:npm/lodash@4.17.21", "mcp:tool/name"} {
		parsed, rewritten, err := Authority(value)
		if err != nil {
			t.Fatalf("Authority(%q) error = %v", value, err)
		}
		if rewritten {
			t.Fatalf("Authority(%q) rewritten = true, want false", value)
		}
		if parsed.User != nil {
			t.Fatalf("Authority(%q).User = %v, want nil", value, parsed.User)
		}
	}
}

// TestAuthorityErrorOmitsTheValue pins the redaction contract: a parse
// failure must never repeat the input, which reaches terminals and logs.
func TestAuthorityErrorOmitsTheValue(t *testing.T) {
	t.Parallel()

	const secret = "sup3r-s3cret-marker"
	_, _, err := Authority("svc://" + secret + "@[" + ":::")
	if err == nil {
		t.Fatal("Authority() error = nil, want a parse failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Authority() error repeats the input value: %q", err)
	}
}

// TestCarriesUserinfoTable pins the fail-closed classifier across the
// readings net/url accepts.
func TestCarriesUserinfoTable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"https://sbom.example.com/sbom.json", false},
		{"https://sbom.example.com/private/sbom.json?token=abc#frag", false},
		{"https://user:secret@sbom.example.com/private/sbom.json", true},
		{"svc:PASSWORD@h.internal:5432/tool", true},
		{"pkg:npm/lodash@4.17.21", false},
		{"mcp:tool/name", false},
		{"mailto:user@example.com", true},
		{"https://exa mple.com/%zz", true},
	} {
		if got := CarriesUserinfo(tc.value); got != tc.want {
			t.Errorf("CarriesUserinfo(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

// TestOpaqueHasAuthorityTable pins the rewrite selector: only an "@"
// ahead of the first "/" marks an opaque body as authority-shaped.
func TestOpaqueHasAuthorityTable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		opaque string
		want   bool
	}{
		{"", false},
		{"PASSWORD@h.internal:5432/tool", true},
		{"PASSWORD@h.internal:5432", true},
		{"tool/name", false},
		{"npm/lodash@4.17.21", false},
		{"no-at-sign", false},
	} {
		if got := opaqueHasAuthority(tc.opaque); got != tc.want {
			t.Errorf("opaqueHasAuthority(%q) = %v, want %v", tc.opaque, got, tc.want)
		}
	}
}

// TestErrWithoutValueStripsInput pins the error hygiene: a *url.Error
// envelope (which quotes the whole URL) is rebuilt as operation plus
// reason, and a non-URL error passes through untouched.
func TestErrWithoutValueStripsInput(t *testing.T) {
	t.Parallel()

	const secret = "sup3r-s3cret-marker"
	// Built with strings.Replace so the invalid URL is not a constant:
	// staticcheck flags url.Parse calls it can prove fail at compile time.
	_, err := url.Parse(strings.Replace("https://[HOST", "HOST", secret, 1))
	if err == nil {
		t.Fatal("url.Parse() error = nil, want a parse failure")
	}
	redacted := errWithoutValue(err)
	if strings.Contains(redacted.Error(), secret) {
		t.Fatalf("errWithoutValue() repeats the input value: %q", redacted)
	}
	if !strings.Contains(redacted.Error(), "parse") {
		t.Fatalf("errWithoutValue() = %q, want the parse operation", redacted)
	}

	sentinel := errors.New("boom")
	if got := errWithoutValue(sentinel); got != sentinel {
		t.Fatalf("errWithoutValue(sentinel) = %v, want the input error", got)
	}
}

// TestParseErrorReasonTable pins the reason classifier: static messages
// pass through, input-quoting shapes map onto fixed text, and anything
// unrecognized — including a future Go message — fails closed.
func TestParseErrorReasonTable(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]string{
		"missing protocol scheme":                        "missing protocol scheme",
		"first path segment in URL cannot contain colon": "first path segment in URL cannot contain colon",
		"net/url: invalid userinfo":                      "net/url: invalid userinfo",
	} {
		if got := ParseErrorReason(errors.New(value)); got != want {
			t.Errorf("ParseErrorReason(%q) = %q, want %q", value, got, want)
		}
	}
	if got := ParseErrorReason(url.EscapeError("%zz")); got != "invalid URL escape" {
		t.Errorf("ParseErrorReason(EscapeError) = %q, want %q", got, "invalid URL escape")
	}
	if got := ParseErrorReason(url.InvalidHostError("bad")); got != "invalid character in host name" {
		t.Errorf("ParseErrorReason(InvalidHostError) = %q, want %q", got, "invalid character in host name")
	}
	if got := ParseErrorReason(errors.New(`invalid port ":secret" after host`)); got != "invalid port after host" {
		t.Errorf("ParseErrorReason(port) = %q, want %q", got, "invalid port after host")
	}
	if got := ParseErrorReason(errors.New("some future go message: xyz")); got != "malformed URL" {
		t.Errorf("ParseErrorReason(unknown) = %q, want %q", got, "malformed URL")
	}
	if got := ParseErrorReason(&url.Error{Op: "parse", URL: "https://secret", Err: errors.New("empty url")}); got != "empty url" {
		t.Errorf("ParseErrorReason(url.Error) = %q, want %q", got, "empty url")
	}
}
