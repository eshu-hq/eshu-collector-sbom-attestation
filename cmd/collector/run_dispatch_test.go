// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"context"
	"testing"
)

// TestRunDispatchesSeedSubcommand proves the run entry point routes the seed
// subcommand to the seeder: an invalid seed flag fails from seed parsing,
// not from claim serving.
func TestRunDispatchesSeedSubcommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"seed", "--bad-flag"}, &bytes.Buffer{}, &stdout, &stderr, nil)
	if err == nil {
		t.Fatal("run(seed --bad-flag) error = nil, want seed flag failure")
	}
}

// TestRunSurfacesClaimFlagErrors proves a malformed claim flag fails fast
// from flag parsing instead of starting the claim loop.
func TestRunSurfacesClaimFlagErrors(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"--sdk-stdio=maybe"}, &bytes.Buffer{}, &stdout, &stderr, nil)
	if err == nil {
		t.Fatal("run(--sdk-stdio=maybe) error = nil, want flag parse failure")
	}
}

// TestSelectImageRefPrefersFlag proves the flag value wins over the
// environment, a lone newline counts as unset, and a nil getenv is safe.
func TestSelectImageRefPrefersFlag(t *testing.T) {
	t.Parallel()

	const ref = "example.com/collector@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	if got := selectImageRef(ref, func(string) string { return "other" }); got != ref {
		t.Errorf("selectImageRef(flag) = %q, want the flag value", got)
	}
	if got := selectImageRef("\n", nil); got != "" {
		t.Errorf("selectImageRef(newline, nil) = %q, want empty", got)
	}
	if got := selectImageRef("", nil); got != "" {
		t.Errorf("selectImageRef(empty, nil) = %q, want empty", got)
	}
}
