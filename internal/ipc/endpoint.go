package ipc

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidEndpoint     = errors.New("ipc: invalid local endpoint")
	ErrEndpointInsecure    = errors.New("ipc: insecure local endpoint")
	ErrEndpointInUse       = errors.New("ipc: local endpoint is already in use")
	ErrEndpointUnavailable = errors.New("ipc: local endpoint became unavailable")
	ErrListenerClosed      = errors.New("ipc: listener is closed")
)

// Endpoint is a validated host-local address resolved by the owner-only
// supervisor registry. Workspace metadata must never be used to construct it.
type Endpoint struct {
	address string
}

// ParseEndpoint validates one platform-native local endpoint.
func ParseEndpoint(address string) (Endpoint, error) {
	if err := validateEndpointAddress(address); err != nil {
		return Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
	}
	return Endpoint{address: address}, nil
}

// String returns the platform-native local address.
func (endpoint Endpoint) String() string {
	return endpoint.address
}

func (endpoint Endpoint) valid() bool {
	return endpoint.address != "" && validateEndpointAddress(endpoint.address) == nil
}
