// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

// TestSDKPinsResolve proves the module builds against the exact published
// pins with no replace directives, and that the pinned fixture pack ships
// schemas for every fact kind this collector emits.
func TestSDKPinsResolve(t *testing.T) {
	t.Parallel()

	var _ sdkcollector.ResultState = sdkcollector.ResultState("complete")
	for _, kind := range []string{
		"sbom.document",
		"sbom.component",
		"sbom.dependency_relationship",
		"sbom.external_reference",
		"attestation.statement",
		"attestation.slsa_provenance",
		"attestation.signature_verification",
		"sbom.warning",
	} {
		schema, ok := fixturepack.SchemaFor(kind)
		if !ok {
			t.Fatalf("pinned fixture pack ships no schema for %q", kind)
		}
		if len(schema) == 0 {
			t.Fatalf("pinned fixture pack ships empty schema for %q", kind)
		}
	}
}
