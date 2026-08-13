package event_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const (
	internalImportPrefix = "github.com/ijonahch/codecomm/internal/"
	codecImport          = "github.com/ijonahch/codecomm/internal/codec"
	cryptoImport         = "github.com/ijonahch/codecomm/internal/crypto"
	domainImport         = "github.com/ijonahch/codecomm/internal/domain"
)

func TestEventLayeringAllowsOnlyLowerInternalPackages(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the event package")
	}
	root := filepath.Dir(currentFile)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read event package: %v", err)
	}

	fileSet := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() ||
			!strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		file, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parse %s: %v", entry.Name(), err)
			continue
		}
		for _, imported := range file.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("unquote import in %s: %v", entry.Name(), err)
				continue
			}
			allowed := importPath == codecImport ||
				importPath == cryptoImport ||
				importPath == domainImport ||
				strings.HasPrefix(importPath, domainImport+"/")
			if strings.HasPrefix(importPath, internalImportPrefix) && !allowed {
				position := fileSet.Position(imported.Pos())
				t.Errorf(
					"%s:%d imports disallowed internal package %q",
					entry.Name(),
					position.Line,
					importPath,
				)
			}
		}
	}
}

func TestPrivilegedAuthorityCallsitesAreRestricted(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the event package")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	restricted := map[string]struct{}{
		"LocalAuthority":    {},
		"NewLocalAuthority": {},
		"OperatorBinding":   {},
		"DaemonBinding":     {},
	}

	err := filepath.WalkDir(repositoryRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		relative, err := filepath.Rel(repositoryRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if strings.HasPrefix(relative, "internal/event/") ||
			strings.HasPrefix(relative, "internal/ipc/") ||
			strings.HasPrefix(relative, "cmd/codecommd/") {
			return nil
		}

		fileSet := token.NewFileSet()
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			t.Errorf("parse %s: %v", relative, err)
			return nil
		}
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if _, forbidden := restricted[identifier.Name]; !forbidden {
				return true
			}
			position := fileSet.Position(identifier.Pos())
			t.Errorf(
				"%s:%d references privileged event authority %q outside codecommd/IPC",
				relative,
				position.Line,
				identifier.Name,
			)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
}
