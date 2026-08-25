//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestDaemonSnapshotRootRejectsWindowsJunctions(t *testing.T) {
	managed := t.TempDir()
	external := t.TempDir()
	externalArtifact := filepath.Join(external, "artifact")
	if err := os.Mkdir(externalArtifact, 0o700); err != nil {
		t.Fatal(err)
	}
	externalRoot := filepath.Join(externalArtifact, "root.json")
	if err := os.WriteFile(
		externalRoot,
		[]byte(`{"external":true}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	junction := filepath.Join(managed, "inventory")
	createDaemonSnapshotTestJunction(t, junction, external)
	if file, err := openDaemonSnapshotPath(junction, true); err == nil {
		_ = file.Close()
		t.Fatal("opened a Windows junction as a trusted snapshot directory")
	} else if !errors.Is(err, errDaemonSnapshotIntegrity) {
		t.Fatalf("open junction error = %v, want snapshot integrity error", err)
	}

	root, err := openDaemonSnapshotPathRoot(managed)
	if err != nil {
		t.Fatalf("open managed snapshot root: %v", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Errorf("close managed snapshot root: %v", err)
		}
	}()
	linkedRoot := filepath.Join(junction, "artifact", "root.json")
	if file, err := root.open(linkedRoot, false); err == nil {
		_ = file.Close()
		t.Fatal("rooted snapshot read followed a Windows junction")
	}

	escaped := filepath.Join(external, "escaped.bin")
	if file, err := root.createFile(
		filepath.Join(junction, "escaped.bin"),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	); err == nil {
		_ = file.Close()
		t.Fatal("rooted snapshot create followed a Windows junction")
	}
	if _, err := os.Lstat(escaped); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed rooted create left an external file: %v", err)
	}

	source := filepath.Join(managed, "rename-source.bin")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.rename(
		source,
		filepath.Join(junction, "renamed.bin"),
		false,
	); err == nil {
		t.Fatal("rooted snapshot rename followed a Windows junction")
	}
	if content, err := os.ReadFile(source); err != nil ||
		!bytes.Equal(content, []byte("source")) {
		t.Fatalf("failed rooted rename changed its source: %q, %v", content, err)
	}

	if err := root.removeAll(
		filepath.Join(junction, "artifact"),
	); err == nil {
		t.Fatal("rooted snapshot cleanup followed a Windows junction")
	}
	if content, err := os.ReadFile(externalRoot); err != nil ||
		!bytes.Equal(content, []byte(`{"external":true}`)) {
		t.Fatalf(
			"failed rooted cleanup altered external content: %q, %v",
			content,
			err,
		)
	}
}

func createDaemonSnapshotTestJunction(
	t testing.TB,
	link string,
	target string,
) {
	t.Helper()
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatalf("create junction directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove junction: %v", err)
		}
	})

	substitute, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		t.Fatalf("encode junction substitute path: %v", err)
	}
	printName, err := windows.UTF16FromString(target)
	if err != nil {
		t.Fatalf("encode junction display path: %v", err)
	}
	pathWords := append(substitute, printName...)
	pathBytes := len(pathWords) * 2
	const (
		reparseHeaderBytes = 8
		mountPointHeader   = 8
	)
	reparseDataLength := mountPointHeader + pathBytes
	if reparseDataLength > int(^uint16(0)) {
		t.Fatal("junction target exceeds Windows reparse buffer")
	}
	buffer := make([]byte, reparseHeaderBytes+reparseDataLength)
	binary.LittleEndian.PutUint32(
		buffer[0:4],
		windows.IO_REPARSE_TAG_MOUNT_POINT,
	)
	binary.LittleEndian.PutUint16(
		buffer[4:6],
		uint16(reparseDataLength),
	)
	binary.LittleEndian.PutUint16(
		buffer[8:10],
		0,
	)
	binary.LittleEndian.PutUint16(
		buffer[10:12],
		uint16((len(substitute)-1)*2),
	)
	binary.LittleEndian.PutUint16(
		buffer[12:14],
		uint16(len(substitute)*2),
	)
	binary.LittleEndian.PutUint16(
		buffer[14:16],
		uint16((len(printName)-1)*2),
	)
	for index, word := range pathWords {
		binary.LittleEndian.PutUint16(
			buffer[reparseHeaderBytes+mountPointHeader+index*2:],
			word,
		)
	}

	extended, err := daemonSnapshotDirectoryWindowsPath(link)
	if err != nil {
		t.Fatalf("normalize junction path: %v", err)
	}
	path, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		t.Fatalf("encode junction path: %v", err)
	}
	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|
			windows.FILE_SHARE_WRITE|
			windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|
			windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		t.Fatalf("open junction directory: %v", err)
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Errorf("close junction handle: %v", err)
		}
	}()
	var returned uint32
	if err := windows.DeviceIoControl(
		handle,
		windows.FSCTL_SET_REPARSE_POINT,
		&buffer[0],
		uint32(len(buffer)),
		nil,
		0,
		&returned,
		nil,
	); err != nil {
		t.Fatalf("create Windows junction: %v", err)
	}
}
