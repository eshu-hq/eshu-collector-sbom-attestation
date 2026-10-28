// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package document

import (
	"errors"
	"testing"
)

// TestMergeContractPayloadNoErrorKeepsExisting proves a failing encode leaves
// the payload untouched and existing keys win over encoded ones, so a
// contract-schema regression can never silently rewrite an emitted fact.
func TestMergeContractPayloadNoErrorKeepsExisting(t *testing.T) {
	t.Parallel()

	payload := map[string]any{"keep": "original"}
	mergeContractPayloadNoError(payload, func() (map[string]any, error) {
		return nil, errors.New("contract encode failed")
	})
	if len(payload) != 1 || payload["keep"] != "original" {
		t.Errorf("payload after failed encode = %v, want untouched", payload)
	}

	mergeContractPayloadNoError(payload, func() (map[string]any, error) {
		return map[string]any{"keep": "overwrite", "fresh": "added"}, nil
	})
	if payload["keep"] != "original" || payload["fresh"] != "added" {
		t.Errorf("payload after merge = %v, want existing keys kept and fresh added", payload)
	}
}
