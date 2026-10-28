// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package packageidentity

import (
	"strings"
	"testing"
)

// TestNormalizeEcosystemAliases proves every documented package-manager alias
// lands on its canonical ecosystem, and unknown or blank input fails closed.
func TestNormalizeEcosystemAliases(t *testing.T) {
	t.Parallel()

	aliased := map[Ecosystem][]string{
		EcosystemNPM:      {"npm", "node", "nodejs", "javascript", "typescript", " NPM "},
		EcosystemPyPI:     {"pypi", "pip", "python"},
		EcosystemGoModule: {"go", "golang", "gomod", "go-module", "go_module"},
		EcosystemMaven:    {"maven", "gradle", "java"},
		EcosystemNuGet:    {"nuget", "dotnet", ".net"},
		EcosystemComposer: {"composer", "packagist", "php"},
		EcosystemRubyGems: {"rubygems", "gem", "ruby"},
		EcosystemCargo:    {"cargo", "crate", "crates", "crates.io", "rust"},
		EcosystemSwift:    {"swift", "swifturl", "swiftpm", "spm", "swift-package-manager"},
		EcosystemHex:      {"hex", "hexpm", "hex.pm"},
		EcosystemPub:      {"pub", "pub.dev", "dart", "dart-pub"},
		EcosystemOS:       {"os", "apk", "alpine", "deb", "debian", "rpm", "rhel", "ubuntu"},
		EcosystemGeneric:  {"generic"},
	}
	for want, aliases := range aliased {
		for _, alias := range aliases {
			if got := NormalizeEcosystem(Ecosystem(alias)); got != want {
				t.Errorf("NormalizeEcosystem(%q) = %q, want %q", alias, got, want)
			}
		}
	}
	for _, unknown := range []string{"", "  ", "foo", "apktool"} {
		if got := NormalizeEcosystem(Ecosystem(unknown)); got != "" {
			t.Errorf("NormalizeEcosystem(%q) = %q, want empty", unknown, got)
		}
	}
}

// TestNormalizeRegistry proves registry hosts lower-case while source path
// casing survives, and blank input stays blank.
func TestNormalizeRegistry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"blank", "", ""},
		{"slashes only", "///", ""},
		{"bare host uppercases", "REGISTRY.NPMJS.ORG", "registry.npmjs.org"},
		{"bare host trims slashes", "/registry.npmjs.org/", "registry.npmjs.org"},
		{"https url lowercases host keeps path case", "https://Proxy.Golang.Org/Example/Casing", "proxy.golang.org/Example/Casing"},
		{"https url bare host", "https://pypi.org/", "pypi.org"},
		{"host path lowercases host keeps path", "Repo.Maven.Apache.Org/maven2", "repo.maven.apache.org/maven2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeRegistry(tc.raw); got != tc.want {
				t.Errorf("NormalizeRegistry(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestNormalizePerEcosystem proves one representative raw identity per
// ecosystem normalizes to its stable PackageID and derived purl.
func TestNormalizePerEcosystem(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		raw          RawIdentity
		wantPackage  string
		wantPURL     string
		wantName     string
		wantNS       string
		wantRegistry string
	}{
		{
			name:         "npm scoped",
			raw:          RawIdentity{Ecosystem: "npm", Registry: "registry.npmjs.org", RawName: "@Scope/Name", Version: "1.2.3"},
			wantPackage:  "npm://registry.npmjs.org/@scope/name",
			wantPURL:     "pkg:npm/%40scope/name@1.2.3",
			wantName:     "@scope/name",
			wantNS:       "scope",
			wantRegistry: "registry.npmjs.org",
		},
		{
			name:         "npm alias node",
			raw:          RawIdentity{Ecosystem: "node", Registry: "registry.npmjs.org", RawName: "Left-Pad"},
			wantPackage:  "npm://registry.npmjs.org/left-pad",
			wantPURL:     "pkg:npm/left-pad",
			wantName:     "left-pad",
			wantRegistry: "registry.npmjs.org",
		},
		{
			name:         "pypi separators fold",
			raw:          RawIdentity{Ecosystem: "pip", Registry: "pypi.org/simple", RawName: "My_Package.Name", Version: "2.0"},
			wantPackage:  "pypi://pypi.org/simple/my-package-name",
			wantPURL:     "pkg:pypi/my-package-name@2.0",
			wantName:     "my-package-name",
			wantRegistry: "pypi.org/simple",
		},
		{
			name:         "gomod keeps module path",
			raw:          RawIdentity{Ecosystem: "go", Registry: "proxy.golang.org", RawName: "github.com/eshu-hq/eshu", Version: "v1.0.0"},
			wantPackage:  "gomod://proxy.golang.org/github.com/eshu-hq/eshu",
			wantPURL:     "pkg:golang/github.com/eshu-hq/eshu@v1.0.0",
			wantName:     "github.com/eshu-hq/eshu",
			wantNS:       "github.com/eshu-hq",
			wantRegistry: "proxy.golang.org",
		},
		{
			name:         "maven group artifact",
			raw:          RawIdentity{Ecosystem: "maven", Registry: "repo.maven.apache.org/maven2", RawName: "core", Namespace: "org.example", Version: "3.1"},
			wantPackage:  "maven://repo.maven.apache.org/maven2/org.example:core",
			wantPURL:     "pkg:maven/org.example/core@3.1",
			wantName:     "core",
			wantNS:       "org.example",
			wantRegistry: "repo.maven.apache.org/maven2",
		},
		{
			name:         "composer vendor slash name",
			raw:          RawIdentity{Ecosystem: "composer", Registry: "repo.packagist.org", RawName: "Vendor/Package"},
			wantPackage:  "composer://repo.packagist.org/vendor/package",
			wantPURL:     "pkg:composer/vendor/package",
			wantName:     "vendor/package",
			wantNS:       "vendor",
			wantRegistry: "repo.packagist.org",
		},
		{
			name:         "nuget lowercases",
			raw:          RawIdentity{Ecosystem: "nuget", Registry: "api.nuget.org/v3/index.json", RawName: "NewtonSoft.Json"},
			wantPackage:  "nuget://api.nuget.org/v3/index.json/newtonsoft.json",
			wantPURL:     "pkg:nuget/newtonsoft.json",
			wantName:     "newtonsoft.json",
			wantRegistry: "api.nuget.org/v3/index.json",
		},
		{
			name:         "rubygems",
			raw:          RawIdentity{Ecosystem: "gem", Registry: "rubygems.org", RawName: "Rails"},
			wantPackage:  "rubygems://rubygems.org/rails",
			wantPURL:     "pkg:gem/rails",
			wantName:     "rails",
			wantRegistry: "rubygems.org",
		},
		{
			name:         "cargo",
			raw:          RawIdentity{Ecosystem: "cargo", Registry: "crates.io", RawName: "Serde"},
			wantPackage:  "cargo://crates.io/serde",
			wantPURL:     "pkg:cargo/serde",
			wantName:     "serde",
			wantRegistry: "crates.io",
		},
		{
			name:         "swift registry becomes namespace",
			raw:          RawIdentity{Ecosystem: "swift", Registry: "ignored.example.com", RawName: "Example.git", Namespace: "github.com/Example/Example.git"},
			wantPackage:  "swift://github.com/example/example/example",
			wantPURL:     "pkg:swift/github.com/example/example/example",
			wantName:     "example",
			wantNS:       "github.com/example/example",
			wantRegistry: "github.com/example/example",
		},
		{
			name:         "hex with namespace",
			raw:          RawIdentity{Ecosystem: "hex", Registry: "hex.pm", RawName: "Phoenix", Namespace: "Org"},
			wantPackage:  "hex://hex.pm/org/phoenix",
			wantPURL:     "pkg:hex/org/phoenix",
			wantName:     "phoenix",
			wantNS:       "org",
			wantRegistry: "hex.pm",
		},
		{
			name:         "hex without namespace",
			raw:          RawIdentity{Ecosystem: "hex", Registry: "hex.pm", RawName: "Cowboy"},
			wantPackage:  "hex://hex.pm/cowboy",
			wantPURL:     "pkg:hex/cowboy",
			wantName:     "cowboy",
			wantRegistry: "hex.pm",
		},
		{
			name:         "pub legacy host rewrites",
			raw:          RawIdentity{Ecosystem: "dart", Registry: "pub.dartlang.org", RawName: "Args"},
			wantPackage:  "pub://pub.dev/args",
			wantPURL:     "pkg:pub/args",
			wantName:     "args",
			wantRegistry: "pub.dev",
		},
		{
			name:         "os distro",
			raw:          RawIdentity{Ecosystem: "deb", Registry: "debian/bookworm", RawName: "OpenSSL"},
			wantPackage:  "os://debian/bookworm/openssl",
			wantPURL:     "pkg:generic/debian/bookworm/openssl",
			wantName:     "openssl",
			wantRegistry: "debian/bookworm",
		},
		{
			name:         "os explicit manager types purl",
			raw:          RawIdentity{Ecosystem: "os", Registry: "debian/bookworm", RawName: "nginx", PackageManager: "deb"},
			wantPackage:  "os://debian/bookworm/nginx",
			wantPURL:     "pkg:deb/debian/bookworm/nginx",
			wantName:     "nginx",
			wantRegistry: "debian/bookworm",
		},
		{
			name:         "generic preserves case",
			raw:          RawIdentity{Ecosystem: "generic", Registry: "example.com", RawName: "MyArtifact", Namespace: "Team"},
			wantPackage:  "generic://example.com/MyArtifact",
			wantPURL:     "pkg:generic/MyArtifact",
			wantName:     "MyArtifact",
			wantNS:       "Team",
			wantRegistry: "example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Normalize(tc.raw)
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if got.PackageID != tc.wantPackage {
				t.Errorf("PackageID = %q, want %q", got.PackageID, tc.wantPackage)
			}
			if got.PURL != tc.wantPURL {
				t.Errorf("PURL = %q, want %q", got.PURL, tc.wantPURL)
			}
			if got.NormalizedName != tc.wantName {
				t.Errorf("NormalizedName = %q, want %q", got.NormalizedName, tc.wantName)
			}
			if got.Namespace != tc.wantNS {
				t.Errorf("Namespace = %q, want %q", got.Namespace, tc.wantNS)
			}
			if got.Registry != tc.wantRegistry {
				t.Errorf("Registry = %q, want %q", got.Registry, tc.wantRegistry)
			}
		})
	}
}

// TestNormalizeKeepsCallerSuppliedRefs proves an explicit purl or bom-ref
// survives normalization, and the bom-ref falls back to purl then package ID.
func TestNormalizeKeepsCallerSuppliedRefs(t *testing.T) {
	t.Parallel()

	base := RawIdentity{Ecosystem: "npm", Registry: "registry.npmjs.org", RawName: "left-pad", Version: "1.3.0"}

	withPURL := base
	withPURL.PURL = "pkg:npm/left-pad@1.3.0?repository_url=https://example.com"
	got, err := Normalize(withPURL)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if got.PURL != withPURL.PURL {
		t.Errorf("PURL = %q, want caller value %q", got.PURL, withPURL.PURL)
	}
	if got.BOMRef != withPURL.PURL {
		t.Errorf("BOMRef = %q, want purl fallback %q", got.BOMRef, withPURL.PURL)
	}

	withBOM := base
	withBOM.BOMRef = "bom-ref-123"
	got, err = Normalize(withBOM)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if got.BOMRef != "bom-ref-123" {
		t.Errorf("BOMRef = %q, want caller value", got.BOMRef)
	}
	if got.PURL != "pkg:npm/left-pad@1.3.0" {
		t.Errorf("PURL = %q, want derived value", got.PURL)
	}

	// No version and no caller refs: the bom-ref falls back to the package ID.
	bare := RawIdentity{Ecosystem: "pypi", Registry: "pypi.org/simple", RawName: "requests"}
	got, err = Normalize(bare)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	// The generated purl is always non-empty, so the bom-ref falls back to
	// it here; the PackageID fallback only fires for a caller-supplied
	// empty purl, which Normalize never produces.
	if got.BOMRef != "pkg:pypi/requests" {
		t.Errorf("BOMRef = %q, want purl fallback pkg:pypi/requests", got.BOMRef)
	}
	if got.PackageManager != "pypi" {
		t.Errorf("PackageManager = %q, want ecosystem default", got.PackageManager)
	}
	if got.RawName != "requests" || got.Version != "" || got.Classifier != "" {
		t.Errorf("raw passthrough = %+v, want trimmed raw fields", got)
	}
}

// TestNormalizeRejectsBadInput proves each required identity field fails
// closed with an error instead of a guessed identity.
func TestNormalizeRejectsBadInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  RawIdentity
		want string
	}{
		{"blank ecosystem", RawIdentity{Registry: "example.com", RawName: "x"}, "ecosystem"},
		{"unknown ecosystem", RawIdentity{Ecosystem: "foo", Registry: "example.com", RawName: "x"}, "ecosystem"},
		{"blank registry", RawIdentity{Ecosystem: "npm", RawName: "x"}, "registry"},
		{"blank name", RawIdentity{Ecosystem: "npm", Registry: "example.com", RawName: "  "}, "name"},
		{"maven without namespace", RawIdentity{Ecosystem: "maven", Registry: "example.com", RawName: "core"}, "namespace"},
		{"scoped npm without name", RawIdentity{Ecosystem: "npm", Registry: "example.com", RawName: "@scope/"}, "@scope/name"},
		{"bare npm scope", RawIdentity{Ecosystem: "npm", Registry: "example.com", RawName: "@scope"}, "@scope/name"},
		{"composer without namespace", RawIdentity{Ecosystem: "composer", Registry: "example.com", RawName: "plain"}, "namespace/name"},
		{"swift without namespace", RawIdentity{Ecosystem: "swift", Registry: "example.com", RawName: "pkg"}, "namespace"},
		{"swift blank name", RawIdentity{Ecosystem: "swift", Registry: "example.com", RawName: "  .git ", Namespace: "github.com/example/pkg"}, "blank"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Normalize(tc.raw); err == nil {
				t.Fatal("Normalize() error = nil, want failure")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Normalize() error = %q, want substring %q", err, tc.want)
			}
		})
	}
}
