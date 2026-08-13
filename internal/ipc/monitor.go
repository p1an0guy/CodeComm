package ipc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type requestObservation struct {
	pipelined    bool
	disconnected bool
}

type requestMonitor struct {
	connection net.Conn
	reader     *bufio.Reader
	done       chan requestObservation
	stopping   atomic.Bool
}

func startRequestMonitor(
	connection net.Conn,
	reader *bufio.Reader,
	cancel context.CancelFunc,
) (*requestMonitor, error) {
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	monitor := &requestMonitor{
		connection: connection,
		reader:     reader,
		done:       make(chan requestObservation, 1),
	}
	go func() {
		_, err := reader.Peek(1)
		observation := requestObservation{}
		switch {
		case err == nil:
			observation.pipelined = true
		case monitor.stopping.Load() && isTimeout(err):
		case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
			observation.disconnected = true
			cancel()
		default:
			// A non-timeout read failure means this stream can no longer
			// carry a response. Treat it as peer loss and fail closed.
			observation.disconnected = true
			cancel()
		}
		monitor.done <- observation
	}()
	return monitor, nil
}

func (monitor *requestMonitor) stop() (requestObservation, error) {
	monitor.stopping.Store(true)
	if err := monitor.connection.SetReadDeadline(time.Now()); err != nil {
		return requestObservation{}, err
	}
	observation := <-monitor.done
	if !observation.pipelined && !observation.disconnected {
		pipelined, err := hasPipelinedBytes(
			monitor.connection,
			monitor.reader,
		)
		if err != nil {
			return requestObservation{}, err
		}
		observation.pipelined = pipelined
	}
	if err := monitor.connection.SetReadDeadline(time.Time{}); err != nil {
		return requestObservation{}, err
	}
	return observation, nil
}
