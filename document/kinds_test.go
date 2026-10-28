// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package document

import (
	"testing"
)

// TestSBOMAttestationFactKinds proves the collector advertises exactly the
// eight fact kinds the schema version covers — no silent additions or drops.
func TestSBOMAttestationFactKinds(t *testing.T) {
	t.Parallel()

	kinds := SBOMAttestationFactKinds()
	if len(kinds) != 8 {
		t.Fatalf("SBOMAttestationFactKinds() has %d kinds, want 8", len(kinds))
	}
	seen := make(map[string]bool, len(kinds))
	for _, kind := range kinds {
		if seen[kind] {
			t.Errorf("SBOMAttestationFactKinds() duplicates %q", kind)
		}
		seen[kind] = true
		version, ok := SBOMAttestationSchemaVersion(kind)
		if !ok || version != SBOMAttestationSchemaVersionV1 {
			t.Errorf("SBOMAttestationSchemaVersion(%q) = (%q, %v), want (%q, true)", kind, version, ok, SBOMAttestationSchemaVersionV1)
		}
	}
	if version, ok := SBOMAttestationSchemaVersion("sbom.unknown"); ok || version != "" {
		t.Errorf("SBOMAttestationSchemaVersion(unknown) = (%q, %v), want (\"\", false)", version, ok)
	}
}
