package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/x/term"
	"github.com/muesli/cancelreader"
)

const maxDecisionInputBytes = 16

func readContextLine(
	ctx context.Context,
	input io.Reader,
	maxBytes int,
	carriageReturnTerminates bool,
) (_ []byte, resultErr error) {
	if ctx == nil || input == nil || maxBytes < 1 {
		return nil, fmt.Errorf("%w: invalid input reader", errInvalidCLI)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, err := cancelreader.NewReader(input)
	if err != nil {
		return nil, err
	}
	cancelFinished := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		reader.Cancel()
		close(cancelFinished)
	})
	defer func() {
		if !stopCancel() {
			<-cancelFinished
		}
		resultErr = errors.Join(resultErr, reader.Close())
	}()

	line := make([]byte, 0, min(maxBytes, 1024))
	var value [1]byte
	for len(line) <= maxBytes {
		count, readErr := reader.Read(value[:])
		if count == 1 {
			switch value[0] {
			case '\n':
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				return line, nil
			case '\r':
				if carriageReturnTerminates {
					return line, nil
				}
			case 0x03:
				if carriageReturnTerminates {
					clear(line)
					return nil, context.Canceled
				}
			}
			line = append(line, value[0])
		}
		switch {
		case readErr == nil:
			if count == 0 {
				continue
			}
		case errors.Is(readErr, cancelreader.ErrCanceled):
			clear(line)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, context.Canceled
		case errors.Is(readErr, io.EOF):
			return line, nil
		case readErr != nil:
			clear(line)
			return nil, readErr
		}
	}
	clear(line)
	return nil, fmt.Errorf("%w: input exceeds limit", errInvalidCLI)
}

func readTerminalSecret(
	ctx context.Context,
	file *os.File,
	maxBytes int,
) (_ []byte, resultErr error) {
	if ctx == nil || file == nil || maxBytes < 1 {
		return nil, fmt.Errorf("%w: terminal input is unavailable", errInvalidCLI)
	}
	state, err := term.MakeRaw(file.Fd())
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, term.Restore(file.Fd(), state))
	}()
	return readContextLine(ctx, file, maxBytes, true)
}
