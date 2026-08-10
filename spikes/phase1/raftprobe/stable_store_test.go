package raftprobe

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"go.etcd.io/bbolt"
)

const (
	storeHelperEnv   = "CODECOMM_PHASE1_STORE_HELPER"
	storePathEnv     = "CODECOMM_PHASE1_STORE_PATH"
	storeRecordCount = 64
)

func openSynchronousStore(path string) (*raftboltdb.BoltStore, error) {
	options := *bbolt.DefaultOptions
	options.Timeout = time.Second
	options.NoFreelistSync = false
	options.NoSync = false
	return raftboltdb.New(raftboltdb.Options{
		Path:        path,
		BoltOptions: &options,
		NoSync:      false,
	})
}

func TestSynchronousStableStoreSurvivesProcessKillAfterAcknowledgement(t *testing.T) {
	if os.Getenv(storeHelperEnv) == "1" {
		runStoreCrashHelper()
		return
	}

	path := filepath.Join(t.TempDir(), "raft.db")
	command := exec.Command(os.Args[0], "-test.run=^TestSynchronousStableStoreSurvivesProcessKillAfterAcknowledgement$")
	command.Env = append(os.Environ(), storeHelperEnv+"=1", storePathEnv+"="+path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open helper stdout: %v", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})

	ack := make(chan string, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr != nil {
			ack <- "read error: " + readErr.Error()
			return
		}
		ack <- line
	}()
	select {
	case line := <-ack:
		if line != "ACK\n" {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("unexpected helper acknowledgement %q; stderr: %s", line, stderr.String())
		}
	case <-time.After(probeTimeout):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("timed out waiting for store helper; stderr: %s", stderr.String())
	}

	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed helper exited successfully")
	}

	store, err := openSynchronousStore(path)
	if err != nil {
		t.Fatalf("reopen killed store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	})

	value, err := store.Get([]byte("stable-key"))
	if err != nil {
		t.Fatalf("read stable value: %v", err)
	}
	if string(value) != "stable-value" {
		t.Fatalf("stable value = %q", value)
	}
	first, err := store.FirstIndex()
	if err != nil {
		t.Fatal(err)
	}
	last, err := store.LastIndex()
	if err != nil {
		t.Fatal(err)
	}
	if first != 1 || last != storeRecordCount {
		t.Fatalf("persisted log range = %d..%d", first, last)
	}
	for index := uint64(1); index <= storeRecordCount; index++ {
		var entry raft.Log
		if err := store.GetLog(index, &entry); err != nil {
			t.Fatalf("read log %d: %v", index, err)
		}
		expected := fmt.Sprintf("entry-%d", index)
		if string(entry.Data) != expected {
			t.Fatalf("log %d = %q, want %q", index, entry.Data, expected)
		}
	}
}

func runStoreCrashHelper() {
	store, err := openSynchronousStore(os.Getenv(storePathEnv))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := store.Set([]byte("stable-key"), []byte("stable-value")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logs := make([]*raft.Log, 0, storeRecordCount)
	for index := uint64(1); index <= storeRecordCount; index++ {
		logs = append(logs, &raft.Log{
			Index: index,
			Term:  1,
			Type:  raft.LogCommand,
			Data:  []byte(fmt.Sprintf("entry-%d", index)),
		})
	}
	runtime.LockOSThread()
	fmt.Fprintln(os.Stderr, "CODECOMM_STORE_LOGS_BEGIN")
	if err := store.StoreLogs(logs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println("ACK")
	runtime.UnlockOSThread()
	for {
		time.Sleep(time.Hour)
	}
}
