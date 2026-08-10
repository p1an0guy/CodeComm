package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyTraceFilesRequiresTwoSuccessfulSyncsBeforeAck(t *testing.T) {
	tests := []struct {
		name    string
		trace   string
		wantErr bool
	}{
		{
			name: "valid",
			trace: "write(2, \"CODECOMM_STORE_LOGS_BEGIN\\n\", 26) = 26\n" +
				"pwrite64(7, \"data\", 4, 0) = 4\n" +
				"fdatasync(7) = 0\n" +
				"pwrite64(7, \"meta\", 4, 4096) = 4\n" +
				"fdatasync(7) = 0\n" +
				"write(1, \"ACK\\n\", 4) = 4\n",
		},
		{
			name: "sync after acknowledgement",
			trace: "write(2, \"CODECOMM_STORE_LOGS_BEGIN\\n\", 26) = 26\n" +
				"pwrite64(7, \"data\", 4, 0) = 4\n" +
				"fdatasync(7) = 0\n" +
				"pwrite64(7, \"meta\", 4, 4096) = 4\n" +
				"write(1, \"ACK\\n\", 4) = 4\n" +
				"fdatasync(7) = 0\n",
			wantErr: true,
		},
		{
			name: "failed sync",
			trace: "write(2, \"CODECOMM_STORE_LOGS_BEGIN\\n\", 26) = 26\n" +
				"pwrite64(7, \"data\", 4, 0) = 4\n" +
				"fdatasync(7) = -1 EIO (Input/output error)\n" +
				"pwrite64(7, \"meta\", 4, 4096) = 4\n" +
				"fdatasync(7) = 0\n" +
				"write(1, \"ACK\\n\", 4) = 4\n",
			wantErr: true,
		},
		{
			name: "different descriptor",
			trace: "write(2, \"CODECOMM_STORE_LOGS_BEGIN\\n\", 26) = 26\n" +
				"pwrite64(7, \"data\", 4, 0) = 4\n" +
				"fdatasync(7) = 0\n" +
				"pwrite64(8, \"meta\", 4, 4096) = 4\n" +
				"fdatasync(8) = 0\n" +
				"write(1, \"ACK\\n\", 4) = 4\n",
			wantErr: true,
		},
		{
			name:    "missing marker",
			trace:   "write(1, \"ACK\\n\", 4) = 4\n",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "trace")
			if err := os.WriteFile(path, []byte(test.trace), 0o600); err != nil {
				t.Fatal(err)
			}
			err := verifyTraceFiles([]string{path})
			if test.wantErr && err == nil {
				t.Fatal("verifyTraceFiles() accepted invalid trace")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("verifyTraceFiles() error = %v", err)
			}
		})
	}
}

// A trace split across per-thread files is the normal shape under strace -ff,
// because the Go runtime moves goroutines between OS threads: the StoreLogs
// writes/syncs and the acknowledgement land in different files. The verifier
// must merge them, while still rejecting every genuine ordering violation.
func TestVerifyTraceFilesMergesPerThreadFiles(t *testing.T) {
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const begin = "write(2, \"CODECOMM_STORE_LOGS_BEGIN\\n\", 26) = 26\n"
	const ack = "write(1, \"ACK\\n\", 4) = 4\n"

	ordered := write("t.100", begin+
		"pwrite64(7, \"data\", 4096, 0) = 4096\n"+
		"fdatasync(7) = 0\n"+
		"pwrite64(7, \"meta\", 4096, 4096) = 4096\n"+
		"fdatasync(7) = 0\n")
	acknowledged := write("t.101", ack)
	if err := verifyTraceFiles([]string{ordered, acknowledged}); err != nil {
		t.Fatalf("split ordered trace should verify: %v", err)
	}

	incomplete := write("u.100", begin+"pwrite64(7, \"data\", 4096, 0) = 4096\n")
	if err := verifyTraceFiles([]string{incomplete, write("u.101", ack)}); err == nil {
		t.Fatal("acknowledgement without a completed sync sequence must fail even when split")
	}
}
