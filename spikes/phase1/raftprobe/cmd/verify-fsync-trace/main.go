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
	sawBegin := false
	for _, path := range paths {
		ok, err := verifyTraceFile(path)
		if err != nil {
			return err
		}
		if ok {
			fmt.Printf("verified StoreLogs sync-before-ack ordering in %s\n", path)
			return nil
		}
		if begun, scanErr := traceHasBeginMarker(path); scanErr == nil && begun {
			sawBegin = true
		}
	}
	// Distinguish "the helper never ran under the tracer" from "it ran but the
	// ordering was wrong". Without this, a glob that missed the forked child and
	// a genuine durability violation produce the same message.
	if sawBegin {
		return fmt.Errorf(
			"StoreLogs began in %d trace file(s) but no acknowledgement followed a complete same-FD data-write/sync/metadata-write/sync sequence",
			len(paths),
		)
	}
	return fmt.Errorf(
		"no trace among %d file(s) contained the StoreLogs begin marker; confirm strace followed the forked helper (-ff) and that the glob collected every per-PID file",
		len(paths),
	)
}

func traceHasBeginMarker(path string) (bool, error) {
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

func verifyTraceFile(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open trace %s: %w", path, err)
	}
	defer file.Close()

	const (
		beginMarker = `write(2, "CODECOMM_STORE_LOGS_BEGIN\n"`
		ackMarker   = `write(1, "ACK\n", 4) = 4`
	)
	started := false
	databaseFD := -1
	dataWritten := false
	dataSynced := false
	metadataWritten := false
	metadataSynced := false
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.Contains(line, beginMarker):
			started = true
			databaseFD = -1
			dataWritten = false
			dataSynced = false
			metadataWritten = false
			metadataSynced = false
		case started && successfulPwrite.MatchString(line):
			match := successfulPwrite.FindStringSubmatch(line)
			fd, _ := strconv.Atoi(match[1])
			if databaseFD == -1 {
				databaseFD = fd
			}
			if fd != databaseFD {
				continue
			}
			if !dataSynced {
				dataWritten = true
			} else if !metadataSynced {
				metadataWritten = true
			}
		case started && successfulSync.MatchString(line):
			match := successfulSync.FindStringSubmatch(line)
			fd, _ := strconv.Atoi(match[1])
			if fd != databaseFD {
				continue
			}
			switch {
			case dataWritten && !dataSynced:
				dataSynced = true
			case dataSynced && metadataWritten && !metadataSynced:
				metadataSynced = true
			}
		case strings.Contains(line, ackMarker):
			if !started {
				return false, fmt.Errorf("%s: acknowledgement preceded StoreLogs marker", path)
			}
			if !metadataSynced {
				return false, fmt.Errorf(
					"%s: acknowledgement preceded same-FD data-write/sync/metadata-write/sync completion",
					path,
				)
			}
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read trace %s: %w", path, err)
	}
	return false, nil
}
