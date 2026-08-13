package domain_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const (
	internalPrefix   = "github.com/ijonahch/codecomm/internal/"
	rootDomainImport = "github.com/ijonahch/codecomm/internal/domain"
)

func TestDomainLayeringRejectsImportsFromOtherInternalLayers(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the domain package")
	}
	root := filepath.Dir(currentFile)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() ||
			!strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}

		fileSet := token.NewFileSet()
		file, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		for _, imported := range file.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("unquote import %s in %s: %v", imported.Path.Value, path, err)
				continue
			}
			if strings.HasPrefix(importPath, internalPrefix) && importPath != rootDomainImport {
				position := fileSet.Position(imported.Pos())
				relative, relativeErr := filepath.Rel(root, path)
				if relativeErr != nil {
					relative = path
				}
				t.Errorf(
					"%s:%d imports disallowed internal package %q",
					relative,
					position.Line,
					importPath,
				)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk domain packages: %v", err)
	}
}
