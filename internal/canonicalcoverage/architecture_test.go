package canonicalcoverage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProviderRemainsOpaqueAndCoverageSigningStaysPackageOwned(
	t *testing.T,
) {
	t.Parallel()

	if kind := reflect.TypeOf(Provider{}).Kind(); kind != reflect.Struct {
		t.Fatalf("Provider kind = %s, want opaque struct", kind)
	}

	root := filepath.Clean(filepath.Join("..", ".."))
	err := filepath.WalkDir(root, func(
		path string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if entry.IsDir() ||
			filepath.Ext(path) != ".go" ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(
			filepath.ToSlash(relative),
			"internal/canonicalcoverage/",
		) {
			return nil
		}
		file, err := parser.ParseFile(
			token.NewFileSet(),
			path,
			nil,
			parser.SkipObjectResolution,
		)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == "SignatureGitCanonicalCoverage" {
				t.Errorf(
					"%s references canonical-coverage signing label outside its owner package",
					relative,
				)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}
}
