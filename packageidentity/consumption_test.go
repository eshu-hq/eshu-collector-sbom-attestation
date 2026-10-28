// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package packageidentity

import (
	"reflect"
	"testing"
)

// TestConsumptionKeysFailClosed proves unknown ecosystems and blank names
// yield no keys, while known ecosystems return sorted, deduplicated keys.
func TestConsumptionKeysFailClosed(t *testing.T) {
	t.Parallel()

	if got := ConsumptionKeys("foo", "requests"); len(got) != 0 {
		t.Errorf("ConsumptionKeys(unknown) = %v, want no keys", got)
	}
	if got := ConsumptionKeys("npm", "  ", ""); len(got) != 0 {
		t.Errorf("ConsumptionKeys(blanks) = %v, want no keys", got)
	}
	got := ConsumptionKeys("npm", "Left-Pad", "left-pad", "@Scope/Name")
	want := []ConsumptionKey{
		{Ecosystem: EcosystemNPM, PackageName: "@scope/name"},
		{Ecosystem: EcosystemNPM, PackageName: "left-pad"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumptionKeys() = %v, want %v", got, want)
	}
}

// TestConsumptionNameCandidates proves the normalized form joins the
// lower-cased form, and unnormalizable input degrades to lower-case only.
func TestConsumptionNameCandidates(t *testing.T) {
	t.Parallel()

	if got := ConsumptionNameCandidates(EcosystemPyPI, "  "); len(got) != 0 {
		t.Errorf("ConsumptionNameCandidates(blank) = %v, want nil", got)
	}
	got := ConsumptionNameCandidates(EcosystemPyPI, "My_Package")
	want := []string{"my-package", "my_package"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumptionNameCandidates(pypi) = %v, want %v", got, want)
	}
	// Maven without a namespace separator cannot normalize, so only the
	// lower-cased form survives — still matchable, never an error.
	got = ConsumptionNameCandidates(EcosystemMaven, "PlainName")
	if !reflect.DeepEqual(got, []string{"plainname"}) {
		t.Errorf("ConsumptionNameCandidates(maven bare) = %v, want [plainname]", got)
	}
	// Maven preserves the raw name casing through normalization (unlike the
	// lower-cased manifest form), so both spellings survive as candidates.
	got = ConsumptionNameCandidates(EcosystemMaven, "org.example:Core")
	want = []string{"org.example/Core", "org.example:core"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumptionNameCandidates(maven) = %v, want %v", got, want)
	}
}

// TestConsumptionKeysFromPURL proves purl-derived keys cover the bare and
// namespaced name forms, and invalid purls yield no keys.
func TestConsumptionKeysFromPURL(t *testing.T) {
	t.Parallel()

	if got := ConsumptionKeysFromPURL("not-a-purl"); len(got) != 0 {
		t.Errorf("ConsumptionKeysFromPURL(invalid) = %v, want nil", got)
	}
	got := ConsumptionKeysFromPURL("pkg:npm/%40scope/name@1.0.0")
	want := []ConsumptionKey{
		{Ecosystem: EcosystemNPM, PackageName: "@scope/name"},
		{Ecosystem: EcosystemNPM, PackageName: "scope/@scope/name"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumptionKeysFromPURL(npm scoped) = %v, want %v", got, want)
	}
	got = ConsumptionKeysFromPURL("pkg:golang/github.com/example/mod@1.0.0")
	want = []ConsumptionKey{{Ecosystem: EcosystemGoModule, PackageName: "github.com/example/mod"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumptionKeysFromPURL(gomod) = %v, want %v", got, want)
	}
}

// TestConsumptionKeysForRegistryIdentity proves registry identities match on
// source, normalized, and joined forms, with the maven colon join added.
func TestConsumptionKeysForRegistryIdentity(t *testing.T) {
	t.Parallel()

	if got := ConsumptionKeysForRegistryIdentity("foo", "x", "x", ""); len(got) != 0 {
		t.Errorf("ConsumptionKeysForRegistryIdentity(unknown) = %v, want nil", got)
	}
	got := ConsumptionKeysForRegistryIdentity("maven", "Core", "core", "org.example")
	want := []ConsumptionKey{
		{Ecosystem: EcosystemMaven, PackageName: "core"},
		{Ecosystem: EcosystemMaven, PackageName: "org.example/core"},
		{Ecosystem: EcosystemMaven, PackageName: "org.example:core"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumptionKeysForRegistryIdentity(maven) = %v, want %v", got, want)
	}
	got = ConsumptionKeysForRegistryIdentity("npm", "Left-Pad", "left-pad", "")
	want = []ConsumptionKey{{Ecosystem: EcosystemNPM, PackageName: "left-pad"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumptionKeysForRegistryIdentity(npm) = %v, want %v", got, want)
	}
}

// TestConsumptionKeysFromPackageID proves canonical default-registry IDs map
// back to keys while custom registries and malformed IDs fail closed.
func TestConsumptionKeysFromPackageID(t *testing.T) {
	t.Parallel()

	got := ConsumptionKeysFromPackageID("npm://registry.npmjs.org/left-pad")
	want := []ConsumptionKey{{Ecosystem: EcosystemNPM, PackageName: "left-pad"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumptionKeysFromPackageID(npm) = %v, want %v", got, want)
	}
	got = ConsumptionKeysFromPackageID("pypi://pypi.org/simple/requests")
	want = []ConsumptionKey{{Ecosystem: EcosystemPyPI, PackageName: "requests"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumptionKeysFromPackageID(pypi) = %v, want %v", got, want)
	}
	for _, id := range []string{
		"",
		"npm://custom.example.com/left-pad",
		"npm://registry.npmjs.org/",
		"unknown://nowhere/pkg",
		"not-an-id",
	} {
		if got := ConsumptionKeysFromPackageID(id); len(got) != 0 {
			t.Errorf("ConsumptionKeysFromPackageID(%q) = %v, want nil", id, got)
		}
	}
}

// TestConsumptionRawNameAndNamespace proves only maven and hex split
// namespace separators; every other ecosystem passes the name through.
func TestConsumptionRawNameAndNamespace(t *testing.T) {
	t.Parallel()

	if name, ns := consumptionRawNameAndNamespace(EcosystemNPM, " @Scope/Name "); name != "@Scope/Name" || ns != "" {
		t.Errorf("consumptionRawNameAndNamespace(npm) = (%q, %q)", name, ns)
	}
	if name, ns := consumptionRawNameAndNamespace(EcosystemMaven, "org.example:Core"); name != "Core" || ns != "org.example" {
		t.Errorf("consumptionRawNameAndNamespace(maven colon) = (%q, %q)", name, ns)
	}
	if name, ns := consumptionRawNameAndNamespace(EcosystemHex, "org/phoenix"); name != "phoenix" || ns != "org" {
		t.Errorf("consumptionRawNameAndNamespace(hex slash) = (%q, %q)", name, ns)
	}
	if name, ns := consumptionRawNameAndNamespace(EcosystemMaven, "plain"); name != "plain" || ns != "" {
		t.Errorf("consumptionRawNameAndNamespace(maven bare) = (%q, %q)", name, ns)
	}
}
