// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package packageidentity

import (
	"testing"
)

// TestNormalizeTwoSegmentName proves composer-style vendor/name splitting for
// explicit namespaces, prefixed raw names, and bare vendor/name values.
func TestNormalizeTwoSegmentName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		raw, ns   string
		wantName  string
		wantNS    string
		wantError bool
	}{
		{"explicit namespace", "Package", "Vendor", "vendor/package", "vendor", false},
		{"prefixed raw keeps form", "Vendor/Package", "Vendor", "vendor/package", "vendor", false},
		{"bare slash splits", "Vendor/Package", "", "vendor/package", "vendor", false},
		{"missing namespace fails", "plain", "", "", "", true},
		{"empty left fails", "/name", "", "", "", true},
		{"empty right fails", "vendor/", "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			name, ns, err := normalizeTwoSegmentName(tc.raw, tc.ns, "composer")
			if tc.wantError {
				if err == nil {
					t.Fatal("normalizeTwoSegmentName() error = nil, want failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeTwoSegmentName() error = %v", err)
			}
			if name != tc.wantName || ns != tc.wantNS {
				t.Errorf("normalizeTwoSegmentName() = (%q, %q), want (%q, %q)", name, ns, tc.wantName, tc.wantNS)
			}
		})
	}
}

// TestNormalizeSwiftName proves git-suffix trimming, nested-path reduction to
// the leaf segment, and the namespace/name requirements.
func TestNormalizeSwiftName(t *testing.T) {
	t.Parallel()

	got, ns, err := normalizeSwiftName("Example.git", "github.com/example/Example.git")
	if err != nil {
		t.Fatalf("normalizeSwiftName() error = %v", err)
	}
	if got != "example" || ns != "github.com/example/example" {
		t.Errorf("normalizeSwiftName() = (%q, %q), want (example, github.com/example/example)", got, ns)
	}

	got, _, err = normalizeSwiftName("ignored", "github.com/example/org/repo/extra")
	if err != nil {
		t.Fatalf("normalizeSwiftName() error = %v", err)
	}
	if got != "ignored" {
		t.Errorf("normalizeSwiftName() name = %q, want ignored", got)
	}

	if _, _, err := normalizeSwiftName("pkg", ""); err == nil {
		t.Error("normalizeSwiftName() without namespace error = nil, want failure")
	}
	// A raw name that is only a git suffix trims to a blank leaf and must
	// fail, not produce an empty normalized name.
	if _, _, err := normalizeSwiftName(" .git ", "github.com/example/pkg"); err == nil {
		t.Error("normalizeSwiftName() with blank leaf error = nil, want failure")
	}
}

// TestNormalizeNPMName proves scoped names split scope from package and bad
// scopes fail instead of guessing.
func TestNormalizeNPMName(t *testing.T) {
	t.Parallel()

	name, ns, err := normalizeNPMName("@Scope/Name")
	if err != nil || name != "@scope/name" || ns != "scope" {
		t.Errorf("normalizeNPMName() = (%q, %q, %v), want (@scope/name, scope, nil)", name, ns, err)
	}
	name, ns, err = normalizeNPMName("Left-Pad")
	if err != nil || name != "left-pad" || ns != "" {
		t.Errorf("normalizeNPMName() = (%q, %q, %v), want (left-pad, , nil)", name, ns, err)
	}
	for _, bad := range []string{"@", "@/", "@/name", "@scope/", "@scope/ "} {
		if _, _, err := normalizeNPMName(bad); err == nil {
			t.Errorf("normalizeNPMName(%q) error = nil, want failure", bad)
		}
	}
}

// TestPackageIDForVariants proves the maven, swift, hex, and default package
// ID shapes each carry their distinguishing segments.
func TestPackageIDForVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                     string
		ecosystem                Ecosystem
		registry, ns, normalized string
		want                     string
	}{
		{"maven uses colon", EcosystemMaven, "repo.maven.apache.org/maven2", "org.example", "core", "maven://repo.maven.apache.org/maven2/org.example:core"},
		{"swift ignores registry", EcosystemSwift, "ignored", "github.com/example", "pkg", "swift://github.com/example/pkg"},
		{"hex with namespace", EcosystemHex, "hex.pm", "org", "phoenix", "hex://hex.pm/org/phoenix"},
		{"hex bare", EcosystemHex, "hex.pm", "", "cowboy", "hex://hex.pm/cowboy"},
		{"default shape", EcosystemNPM, "registry.npmjs.org", "scope", "@scope/name", "npm://registry.npmjs.org/@scope/name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := packageIDFor(tc.ecosystem, tc.registry, tc.ns, tc.normalized); got != tc.want {
				t.Errorf("packageIDFor() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPurlTypeAndPath proves the golang/gem/os type aliases and the per-
// ecosystem path shapes, including the npm scope escape.
func TestPurlTypeAndPath(t *testing.T) {
	t.Parallel()

	if got := purlTypeFor(EcosystemGoModule, ""); got != "golang" {
		t.Errorf("purlTypeFor(gomod) = %q, want golang", got)
	}
	if got := purlTypeFor(EcosystemRubyGems, ""); got != "gem" {
		t.Errorf("purlTypeFor(rubygems) = %q, want gem", got)
	}
	if got := purlTypeFor(EcosystemOS, "deb"); got != "deb" {
		t.Errorf("purlTypeFor(os, deb) = %q, want deb", got)
	}
	if got := purlTypeFor(EcosystemOS, ""); got != "generic" {
		t.Errorf("purlTypeFor(os, empty) = %q, want generic", got)
	}
	if got := purlTypeFor(EcosystemOS, "os"); got != "generic" {
		t.Errorf("purlTypeFor(os, os) = %q, want generic", got)
	}
	if got := purlTypeFor(EcosystemNPM, ""); got != "npm" {
		t.Errorf("purlTypeFor(npm) = %q, want npm", got)
	}

	if got := packageURLFor(EcosystemNPM, "npm", "registry.npmjs.org", "scope", "@scope/name", "1.0.0"); got != "pkg:npm/%40scope/name@1.0.0" {
		t.Errorf("packageURLFor(npm scoped) = %q", got)
	}
	if got := packageURLFor(EcosystemPyPI, "pypi", "pypi.org/simple", "", "requests", ""); got != "pkg:pypi/requests" {
		t.Errorf("packageURLFor(pypi unversioned) = %q", got)
	}
	if got := encodeNPMNameForPURL("left-pad"); got != "left-pad" {
		t.Errorf("encodeNPMNameForPURL(bare) = %q, want left-pad", got)
	}

	paths := []struct {
		name                     string
		ecosystem                Ecosystem
		registry, ns, normalized string
		want                     string
	}{
		{"npm scoped escaped", EcosystemNPM, "r", "scope", "@scope/name", "%40scope/name"},
		{"maven group path", EcosystemMaven, "r", "org.example", "core", "org.example/core"},
		{"swift namespaced", EcosystemSwift, "r", "github.com/example", "pkg", "github.com/example/pkg"},
		{"hex namespaced", EcosystemHex, "r", "org", "phoenix", "org/phoenix"},
		{"hex bare", EcosystemHex, "r", "", "cowboy", "cowboy"},
		{"os registry prefixed", EcosystemOS, "debian/bookworm", "", "openssl", "debian/bookworm/openssl"},
		{"default trims slashes", EcosystemPyPI, "r", "", "/requests/", "requests"},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := purlPathFor(tc.ecosystem, tc.registry, tc.ns, tc.normalized); got != tc.want {
				t.Errorf("purlPathFor() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSmallIdentityHelpers proves the package-manager default, module
// namespace slicing (including the vN-suffix form), and blank folding.
func TestSmallIdentityHelpers(t *testing.T) {
	t.Parallel()

	if got := normalizePackageManager(" NPM ", EcosystemPyPI); got != "npm" {
		t.Errorf("normalizePackageManager(explicit) = %q, want npm", got)
	}
	if got := normalizePackageManager("  ", EcosystemGoModule); got != "gomod" {
		t.Errorf("normalizePackageManager(blank) = %q, want gomod", got)
	}
	if got := goModuleNamespace("github.com/example/mod"); got != "github.com/example" {
		t.Errorf("goModuleNamespace() = %q", got)
	}
	if got := goModuleNamespace("github.com/example/mod/v2"); got != "github.com/example/mod" {
		t.Errorf("goModuleNamespace(v-suffix) = %q", got)
	}
	if got := goModuleNamespace("single"); got != "" {
		t.Errorf("goModuleNamespace(bare) = %q, want empty", got)
	}
	for value, want := range map[string]bool{"123": true, "": false, "12a": false, "v2": false} {
		if got := allDigits(value); got != want {
			t.Errorf("allDigits(%q) = %v, want %v", value, got, want)
		}
	}
	if got := firstNonBlank("  ", "", " kept "); got != "kept" {
		t.Errorf("firstNonBlank() = %q, want kept", got)
	}
	if got := firstNonBlank(" ", "\t"); got != "" {
		t.Errorf("firstNonBlank(all blank) = %q, want empty", got)
	}
}
