package main

import (
	"os"
	"path/filepath"
	"strings"
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

// CI traces the %desc syscall class rather than an enumerated list, because
// naming a syscall the running kernel lacks (pwrite on x86-64) makes strace exit
// before tracing anything. The verifier must therefore ignore unrelated
// descriptor traffic while still pinning the ordering to the database fd.
func TestVerifyTraceFilesIgnoresUnrelatedDescriptorTraffic(t *testing.T) {
	const trace = `1234 openat(AT_FDCWD, "/tmp/raft.db", O_RDWR|O_CREAT, 0600) = 7
1234 write(2, "CODECOMM_STORE_LOGS_BEGIN\n", 26) = 26
1234 read(3, "x", 1) = 1
1234 pwrite64(7, "data", 4096, 0) = 4096
1234 write(5, "unrelated log\n", 14) = 14
1234 fdatasync(7) = 0
1240 pwrite64(7, "meta", 4096, 4096) = 4096
1240 fstat(7, {st_size=8192}) = 0
1240 fdatasync(7) = 0
1234 write(1, "ACK\n", 4) = 4
1234 close(7) = 0
`
	path := filepath.Join(t.TempDir(), "desc.txt")
	if err := os.WriteFile(path, []byte(trace), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyTraceFiles([]string{path}); err != nil {
		t.Fatalf("noisy but correctly ordered trace should verify: %v", err)
	}

	// The same noise must not hide a sync of the wrong descriptor.
	bad := strings.Replace(trace, "1234 fdatasync(7) = 0", "1234 fdatasync(9) = 0", 1)
	badPath := filepath.Join(t.TempDir(), "desc_bad.txt")
	if err := os.WriteFile(badPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyTraceFiles([]string{badPath}); err == nil {
		t.Fatal("a sync of the wrong descriptor must fail even amid unrelated traffic")
	}
}

// strace truncates traced strings (-s, default 32) and a write is permitted to
// be short, so pinning the marker lines to an exact rendering — byte count and
// return value included — made the ordering proof fail on formatting rather than
// on durability. These shapes must all verify.
func TestVerifyTraceFilesToleratesMarkerRenderingVariation(t *testing.T) {
	body := "pwrite64(7, \"data\"..., 4096, 0) = 4096\n" +
		"fdatasync(7) = 0\n" +
		"pwrite64(7, \"meta\"..., 4096, 4096) = 4096\n" +
		"fdatasync(7) = 0\n"

	for name, trace := range map[string]string{
		"truncated markers": "write(2, \"CODECOMM_STORE_LOGS_BEGIN\"..., 26) = 26\n" + body +
			"write(1, \"ACK\"..., 4) = 4\n",
		"short write": "write(2, \"CODECOMM_STORE_LOGS_BEGIN\\n\", 26) = 26\n" + body +
			"write(1, \"ACK\\n\", 4) = 3\n",
		"pid prefixed": "4242 write(2, \"CODECOMM_STORE_LOGS_BEGIN\\n\", 26) = 26\n" +
			"4242 pwrite64(7, \"data\", 4096, 0) = 4096\n" +
			"4242 fdatasync(7) = 0\n" +
			"4250 pwrite64(7, \"meta\", 4096, 4096) = 4096\n" +
			"4250 fdatasync(7) = 0\n" +
			"4242 write(1, \"ACK\\n\", 4) = 4\n",
	} {
		path := filepath.Join(t.TempDir(), "trace.txt")
		if err := os.WriteFile(path, []byte(trace), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verifyTraceFiles([]string{path}); err != nil {
			t.Errorf("%s should verify: %v", name, err)
		}
	}

	// Tolerating the rendering must not tolerate a missing sync.
	unsynced := "write(2, \"CODECOMM_STORE_LOGS_BEGIN\"..., 26) = 26\n" +
		"pwrite64(7, \"data\"..., 4096, 0) = 4096\n" +
		"write(1, \"ACK\"..., 4) = 4\n"
	path := filepath.Join(t.TempDir(), "unsynced.txt")
	if err := os.WriteFile(path, []byte(unsynced), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyTraceFiles([]string{path}); err == nil {
		t.Fatal("an acknowledgement with no sync must fail regardless of marker rendering")
	}
}
