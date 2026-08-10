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
