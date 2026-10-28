// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package packageidentity

import (
	"strings"
	"testing"
)

// TestDefaultRegistryCoversEcosystems proves every canonical ecosystem has a
// pinned default registry and unknown input fails closed to "unknown".
func TestDefaultRegistryCoversEcosystems(t *testing.T) {
	t.Parallel()

	want := map[Ecosystem]string{
		EcosystemNPM:      "registry.npmjs.org",
		EcosystemPyPI:     "pypi.org/simple",
		EcosystemGoModule: "proxy.golang.org",
		EcosystemMaven:    "repo.maven.apache.org/maven2",
		EcosystemNuGet:    "api.nuget.org/v3/index.json",
		EcosystemComposer: "repo.packagist.org",
		EcosystemRubyGems: "rubygems.org",
		EcosystemCargo:    "crates.io",
		EcosystemSwift:    "swift-package-manager",
		EcosystemHex:      "hex.pm",
		EcosystemPub:      "pub.dev",
		EcosystemOS:       "os",
		EcosystemGeneric:  "unknown",
	}
	for ecosystem, registry := range want {
		if got := DefaultRegistry(ecosystem); got != registry {
			t.Errorf("DefaultRegistry(%q) = %q, want %q", ecosystem, got, registry)
		}
	}
	if got := DefaultRegistry("foo"); got != "unknown" {
		t.Errorf("DefaultRegistry(foo) = %q, want unknown", got)
	}
	// Aliases resolve through the same table: "node" is npm, not unknown.
	if got := DefaultRegistry("node"); got != "registry.npmjs.org" {
		t.Errorf("DefaultRegistry(node) = %q, want the npm registry", got)
	}
}

// TestPackageIDFromPURL proves purl-only SBOM sources correlate onto the same
// canonical identity Normalize produces, and that blank or non-purl input is
// a normal empty result rather than an error.
func TestPackageIDFromPURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		purl string
		want string
	}{
		{"npm with version qualifiers subpath", "pkg:npm/%40scope/name@1.2.3?repository_url=https://example.com#sub", "npm://registry.npmjs.org/@scope/name"},
		{"pypi unversioned", "pkg:pypi/requests", "pypi://pypi.org/simple/requests"},
		{"gomod keeps full path", "pkg:golang/github.com/eshu-hq/eshu@v1.0.0", "gomod://proxy.golang.org/github.com/eshu-hq/eshu"},
		{"maven group path", "pkg:maven/org.example/core@3.1", "maven://repo.maven.apache.org/maven2/org.example:core"},
		{"blank", "", ""},
		{"whitespace", "   ", ""},
		{"non-purl", "not-a-purl", ""},
		{"bare scheme", "pkg:", ""},
		{"type without path", "pkg:npm", ""},
		{"empty name", "pkg:npm/", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := PackageIDFromPURL(tc.purl)
			if err != nil {
				t.Fatalf("PackageIDFromPURL(%q) error = %v", tc.purl, err)
			}
			if got != tc.want {
				t.Errorf("PackageIDFromPURL(%q) = %q, want %q", tc.purl, got, tc.want)
			}
		})
	}
}

// TestPackageIDFromPURLSurfacesNormalizeErrors proves a purl that parses but
// cannot normalize (here: an unknown ecosystem) returns a wrapped error that
// names the purl, so callers can distinguish bad data from absent data.
func TestPackageIDFromPURLSurfacesNormalizeErrors(t *testing.T) {
	t.Parallel()

	if _, err := PackageIDFromPURL("pkg:foo/bar@1.0"); err == nil {
		t.Fatal("PackageIDFromPURL(unknown ecosystem) error = nil, want failure")
	} else if !strings.Contains(err.Error(), "pkg:foo/bar@1.0") {
		t.Errorf("PackageIDFromPURL() error = %q, want the purl named", err)
	}
}

// TestParsePURLBranches proves version/qualifier/subpath stripping, the npm
// scope fold, the gomod full-path rule, and the OS registry/manager split.
func TestParsePURLBranches(t *testing.T) {
	t.Parallel()

	raw, ok := parsePURLToRawIdentity("pkg:npm/%40scope/name@1.0.0")
	if !ok {
		t.Fatal("parsePURLToRawIdentity(npm scoped) ok = false")
	}
	if raw.RawName != "@scope/name" || raw.Namespace != "scope" || raw.Version != "1.0.0" {
		t.Errorf("parsePURLToRawIdentity(npm scoped) = %+v", raw)
	}

	raw, ok = parsePURLToRawIdentity("pkg:deb/debian/nginx@1.24.0?arch=amd64")
	if !ok {
		t.Fatal("parsePURLToRawIdentity(os) ok = false")
	}
	if raw.Ecosystem != EcosystemOS || raw.Registry != "debian" || raw.RawName != "nginx" || raw.PackageManager != "deb" {
		t.Errorf("parsePURLToRawIdentity(os) = %+v", raw)
	}

	raw, ok = parsePURLToRawIdentity("pkg:golang/github.com/example/mod/v2@2.0.0")
	if !ok {
		t.Fatal("parsePURLToRawIdentity(gomod) ok = false")
	}
	if raw.RawName != "github.com/example/mod/v2" || raw.Namespace != "" {
		t.Errorf("parsePURLToRawIdentity(gomod) = %+v", raw)
	}

	// An invalid percent-escape keeps the raw path instead of failing: the
	// identity still normalizes from the literal text.
	raw, ok = parsePURLToRawIdentity("pkg:npm/%zz@1.0.0")
	if !ok || raw.RawName != "%zz" {
		t.Errorf("parsePURLToRawIdentity(bad escape) = (%+v, %v)", raw, ok)
	}

	if eco := canonicalPURLEcosystem("golang"); eco != EcosystemGoModule {
		t.Errorf("canonicalPURLEcosystem(golang) = %q, want gomod", eco)
	}
	if eco := canonicalPURLEcosystem("Foo"); eco != Ecosystem("foo") {
		t.Errorf("canonicalPURLEcosystem(Foo) = %q, want lowercased fallback", eco)
	}
}
