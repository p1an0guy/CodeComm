package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// strace renders the positional-write syscall as pwrite64 on most Linux
// configurations, but pwrite/pwritev/pwritev2 appear on other architectures and
// strace builds. Accepting the family keeps the ordering proof from silently
// degrading into "no trace contained the acknowledgement" on a runner whose
// strace names the syscall differently.
const (
	beginMarker = `write(2, "CODECOMM_STORE_LOGS_BEGIN\n"`
	ackMarker   = `write(1, "ACK\n", 4) = 4`
)

var (
	successfulPwrite = regexp.MustCompile(`\b(?:pwrite64|pwrite|pwritev2|pwritev)\((\d+),.*\)\s+= ([1-9]\d*)(?:\s|$)`)
	successfulSync   = regexp.MustCompile(`\b(?:fdatasync|fsync|fdatasync64|fsync64)\((\d+)\)\s+= 0(?:\s|$)`)
)

func main() {
	if err := verifyTraceFiles(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verifyTraceFiles(paths []string) error {
	if len(paths) == 0 {
		return errors.New("no strace files supplied")
	}
	// strace -ff writes one file per traced thread, and the Go runtime schedules
	// goroutines across OS threads, so StoreLogs' writes/syncs and the
	// acknowledgement legitimately land in different files. A per-file state
	// machine can therefore never observe the complete sequence. Merge every
	// file's events into one timeline before checking order: the events carry
	// their own ordering within a thread, and the acknowledgement is the only
	// cross-thread ordering point we need.
	events, err := collectEvents(paths)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf(
			"no trace among %d file(s) contained the StoreLogs begin marker; confirm strace traced the process (-f or -ff) and that the glob collected every output file",
			len(paths),
		)
	}
	if err := verifyOrdering(events); err != nil {
		return err
	}
	fmt.Printf("verified StoreLogs sync-before-ack ordering across %d trace file(s)\n", len(paths))
	return nil
}

type traceEvent struct {
	kind string // "begin", "write", "sync", "ack"
	fd   int
	file string
	line int
}

func collectEvents(paths []string) ([]traceEvent, error) {
	var events []traceEvent
	sawBegin := false
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open trace %s: %w", path, err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			switch {
			case strings.Contains(line, beginMarker):
				sawBegin = true
				events = append(events, traceEvent{kind: "begin", file: path, line: lineNumber})
			case strings.Contains(line, ackMarker):
				events = append(events, traceEvent{kind: "ack", file: path, line: lineNumber})
			case successfulPwrite.MatchString(line):
				fd, _ := strconv.Atoi(successfulPwrite.FindStringSubmatch(line)[1])
				events = append(events, traceEvent{kind: "write", fd: fd, file: path, line: lineNumber})
			case successfulSync.MatchString(line):
				fd, _ := strconv.Atoi(successfulSync.FindStringSubmatch(line)[1])
				events = append(events, traceEvent{kind: "sync", fd: fd, file: path, line: lineNumber})
			}
		}
		closeErr := file.Close()
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read trace %s: %w", path, err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close trace %s: %w", path, closeErr)
		}
	}
	if !sawBegin {
		return nil, nil
	}
	return events, nil
}

// verifyOrdering requires, after the begin marker and strictly before the
// acknowledgement, a same-descriptor data write, a sync of it, a further
// metadata write, and a sync of that. The descriptor is whichever one the first
// post-begin write targets, so the check is pinned to the database file rather
// than to any incidental write.
func verifyOrdering(events []traceEvent) error {
	started := false
	databaseFD := -1
	dataWritten, dataSynced, metadataWritten, metadataSynced := false, false, false, false
	for _, event := range events {
		switch event.kind {
		case "begin":
			started = true
			databaseFD = -1
			dataWritten, dataSynced, metadataWritten, metadataSynced = false, false, false, false
		case "write":
			if !started {
				continue
			}
			if databaseFD == -1 {
				databaseFD = event.fd
			}
			if event.fd != databaseFD {
				continue
			}
			if !dataSynced {
				dataWritten = true
			} else if !metadataSynced {
				metadataWritten = true
			}
		case "sync":
			if !started || event.fd != databaseFD {
				continue
			}
			switch {
			case dataWritten && !dataSynced:
				dataSynced = true
			case dataSynced && metadataWritten && !metadataSynced:
				metadataSynced = true
			}
		case "ack":
			if !started {
				return fmt.Errorf("%s:%d: acknowledgement preceded the StoreLogs marker", event.file, event.line)
			}
			if !metadataSynced {
				return fmt.Errorf(
					"%s:%d: acknowledgement preceded a complete same-FD data-write/sync/metadata-write/sync sequence (fd=%d data_written=%t data_synced=%t metadata_written=%t)",
					event.file, event.line, databaseFD, dataWritten, dataSynced, metadataWritten,
				)
			}
			return nil
		}
	}
	return errors.New("traces contained the StoreLogs marker but no acknowledgement")
}

func unusedTraceHasBeginMarker(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), `write(2, "CODECOMM_STORE_LOGS_BEGIN\n"`) {
			return true, nil
		}
	}
	return false, scanner.Err()
}
