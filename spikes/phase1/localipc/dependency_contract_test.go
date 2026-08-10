package localipc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoWinIOAlwaysRejectsRemoteNamedPipeClients(t *testing.T) {
	command := exec.Command("go", "list", "-m", "-f", "{{.Version}}\n{{.Dir}}", "github.com/Microsoft/go-winio")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("locate go-winio module: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		t.Fatalf("unexpected go list output %q", output)
	}
	if lines[0] != "v0.6.2" {
		t.Fatalf("go-winio version = %q, want reviewed v0.6.2", lines[0])
	}

	sourcePath := filepath.Join(lines[1], "pipe.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read go-winio named-pipe implementation: %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), sourcePath, source, 0)
	if err != nil {
		t.Fatalf("parse go-winio named-pipe implementation: %v", err)
	}

	var function *ast.FuncDecl
	for _, declaration := range file.Decls {
		candidate, ok := declaration.(*ast.FuncDecl)
		if ok && candidate.Name.Name == "makeServerPipeHandle" {
			function = candidate
			break
		}
	}
	if function == nil {
		t.Fatal("go-winio makeServerPipeHandle implementation not found")
	}

	declaresRejectionFlag := false
	passesFlagToCreate := false
	invalidTypeMutation := false
	ast.Inspect(function, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.AssignStmt:
			if len(value.Lhs) != 1 {
				return true
			}
			left, ok := value.Lhs[0].(*ast.Ident)
			if !ok || left.Name != "typ" {
				return true
			}
			if value.Tok != token.DEFINE {
				invalidTypeMutation = invalidTypeMutation || value.Tok != token.OR_ASSIGN
				return true
			}
			if len(value.Rhs) != 1 {
				return true
			}
			conversion, ok := value.Rhs[0].(*ast.CallExpr)
			if !ok || len(conversion.Args) != 1 {
				return true
			}
			selector, ok := conversion.Args[0].(*ast.SelectorExpr)
			if !ok {
				return true
			}
			packageName, packageOK := selector.X.(*ast.Ident)
			declaresRejectionFlag = packageOK && packageName.Name == "windows" &&
				selector.Sel.Name == "FILE_PIPE_REJECT_REMOTE_CLIENTS"
		case *ast.CallExpr:
			callee, ok := value.Fun.(*ast.Ident)
			if !ok || callee.Name != "ntCreateNamedPipeFile" || len(value.Args) <= 7 {
				return true
			}
			argument, ok := value.Args[7].(*ast.Ident)
			passesFlagToCreate = ok && argument.Name == "typ"
		}
		return true
	})
	if !declaresRejectionFlag || !passesFlagToCreate || invalidTypeMutation {
		t.Fatal("reviewed implementation no longer passes FILE_PIPE_REJECT_REMOTE_CLIENTS to pipe creation")
	}
}
