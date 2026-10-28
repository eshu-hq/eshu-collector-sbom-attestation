// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// coreModulePath is the Eshu core module. The pinned extraction SDKs live
// under github.com/eshu-hq/eshu-sdk, a different prefix.
const coreModulePath = "github.com/eshu-hq/eshu/go"

// TestImportBoundaryRejectsCoreAndCrossCollectorImports is the CI gate that
// keeps a standalone collector repository standalone: no Eshu internal
// implementation imports and no cross-collector implementation imports. Only
// the published SDK modules plus the standard library and yaml are allowed.
// The self-import prefix is derived from go.mod so renaming the module can
// never desync this allowlist.
func TestImportBoundaryRejectsCoreAndCrossCollectorImports(t *testing.T) {
	t.Parallel()

	prefixes := allowedImportPrefixes(modulePath(t))
	// coreModulePath documents the forbidden Eshu core prefix. Fail closed
	// if the allowlist ever admits it: the violations scan below only
	// reports imports outside the allowlist, so an admitted core prefix
	// would pass silently.
	if hasAllowedPrefix(coreModulePath, prefixes) {
		t.Fatalf("allowlist admits the forbidden core module %q", coreModulePath)
	}
	violations, err := importViolations(".", prefixes)
	if err != nil {
		t.Fatalf("importViolations() error = %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("forbidden imports:\n%s", strings.Join(violations, "\n"))
	}
}

func allowedImportPrefixes(module string) []string {
	return []string{
		module,
		"github.com/eshu-hq/eshu-sdk/collector",
		"github.com/eshu-hq/eshu-sdk/factschema",
		"golang.org/x/mod",
		"gopkg.in/yaml.v3",
	}
}

// importViolations parses every .go file under root and reports each import
// outside allowedPrefixes. Every directory is scanned, scripts/ and nested
// testdata/ included, so a forbidden import cannot hide in a helper tree.
// Only .git and top-level testdata/ directories (fixture data, whose .go.txt
// files are not compiled) are skipped.
func importViolations(root string, allowedPrefixes []string) ([]string, error) {
	var violations []string
	walk := func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			if rel == ".git" || rel == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if importPath == "C" {
				violations = append(violations, path+": cgo import is not allowed")
				continue
			}
			if isStandardOrRelative(importPath) || hasAllowedPrefix(importPath, allowedPrefixes) {
				continue
			}
			violations = append(violations, path+": import "+importPath)
		}
		return nil
	}
	if err := filepath.WalkDir(root, walk); err != nil {
		return nil, err
	}
	return violations, nil
}

func hasAllowedPrefix(importPath string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
			return true
		}
	}
	return false
}

// modulePath reads the repository's own module path from go.mod so the
// self-import allowlist entry tracks renames automatically.
func modulePath(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("os.ReadFile(go.mod) error = %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			if strings.TrimSpace(path) == "" {
				break
			}
			return strings.TrimSpace(path)
		}
	}
	t.Fatal("go.mod declares no module path")
	return ""
}

func isStandardOrRelative(importPath string) bool {
	if strings.HasPrefix(importPath, ".") {
		return true
	}
	first, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(first, ".")
}
