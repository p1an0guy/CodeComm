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

var (
	successfulPwrite = regexp.MustCompile(`\bpwrite64\((\d+),.*\)\s+= ([1-9]\d*)(?:\s|$)`)
	successfulSync   = regexp.MustCompile(`\b(?:fdatasync|fsync)\((\d+)\)\s+= 0(?:\s|$)`)
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
	for _, path := range paths {
		ok, err := verifyTraceFile(path)
		if err != nil {
			return err
		}
		if ok {
			fmt.Printf("verified StoreLogs sync-before-ack ordering in %s\n", path)
			return nil
		}
	}
	return errors.New("no trace contained the StoreLogs acknowledgement")
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
