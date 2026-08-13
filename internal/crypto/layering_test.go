package crypto_test

import (
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
)

func TestCryptoLayeringAllowsOnlyCodecInternalImport(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the crypto package")
	}
	root := filepath.Dir(currentFile)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read crypto package: %v", err)
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
			if strings.HasPrefix(importPath, internalImportPrefix) && importPath != codecImport {
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
