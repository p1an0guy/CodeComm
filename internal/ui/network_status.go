package ui

import (
	"context"
	"fmt"
	"net/netip"
	"unicode"
	"unicode/utf8"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/store"
)

const maxNetworkStatusErrorBytes = 1024

type MulticastState string

const (
	MulticastDisabled  MulticastState = "disabled"
	MulticastAvailable MulticastState = "available"
	MulticastDegraded  MulticastState = "degraded"
)

// NetworkStatusSource supplies bounded device-local network observations.
type NetworkStatusSource interface {
	NetworkStatus(context.Context) (NetworkStatus, error)
}

type NetworkStatus struct {
	MulticastState      string   `json:"multicast_state"`
	MulticastError      *string  `json:"multicast_error"`
	SelectedAddresses   []string `json:"selected_addresses"`
	ManualEndpointCount uint64   `json:"manual_endpoint_count"`
}

func disabledNetworkStatus() NetworkStatus {
	return NetworkStatus{
		MulticastState:    string(MulticastDisabled),
		SelectedAddresses: []string{},
	}
}

func (value NetworkStatus) validate() error {
	state := MulticastState(value.MulticastState)
	if value.SelectedAddresses == nil ||
		value.ManualEndpointCount > store.ManualEndpointsPerSessionMax ||
		!domain.ValidUnsignedInteger(value.ManualEndpointCount) {
		return fmt.Errorf("ui: invalid network status")
	}
	switch state {
	case MulticastDisabled:
		if value.MulticastError != nil ||
			len(value.SelectedAddresses) != 0 {
			return fmt.Errorf("ui: invalid disabled multicast status")
		}
	case MulticastAvailable:
		if value.MulticastError != nil ||
			len(value.SelectedAddresses) == 0 {
			return fmt.Errorf("ui: invalid available multicast status")
		}
	case MulticastDegraded:
		if value.MulticastError == nil ||
			!validNetworkStatusError(*value.MulticastError) {
			return fmt.Errorf("ui: invalid degraded multicast status")
		}
	default:
		return fmt.Errorf("ui: invalid multicast state")
	}
	var previous netip.Addr
	for index, text := range value.SelectedAddresses {
		address, err := netip.ParseAddr(text)
		if err != nil ||
			address.String() != text ||
			address.IsLoopback() ||
			address.IsUnspecified() ||
			address.IsMulticast() ||
			!(address.IsGlobalUnicast() ||
				address.IsLinkLocalUnicast()) ||
			index > 0 && address.Compare(previous) <= 0 {
			return fmt.Errorf("ui: invalid selected network address")
		}
		previous = address
	}
	return nil
}

func validNetworkStatusError(value string) bool {
	if value == "" ||
		len(value) > maxNetworkStatusErrorBytes ||
		!utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
