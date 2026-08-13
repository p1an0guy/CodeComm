// Package transport implements CodeComm peer transport authentication and
// plane isolation.
package transport

import "errors"

const (
	ALPNPairing   = "codecomm-pairing/1"
	ALPNConsensus = "codecomm-consensus/1"
	ALPNContent   = "codecomm-content/1"
)

var ErrInvalidALPNOffer = errors.New("transport: invalid ALPN offer")

// Plane is the closed network surface selected before certificate parsing.
type Plane string

const (
	PlanePairing   Plane = "pairing"
	PlaneConsensus Plane = "consensus"
	PlaneContent   Plane = "content"
)

// SelectPlane requires one exact CodeComm ALPN and rejects downgrade or
// cross-plane offers.
func SelectPlane(offered []string) (Plane, error) {
	if len(offered) != 1 {
		return "", ErrInvalidALPNOffer
	}
	switch offered[0] {
	case ALPNPairing:
		return PlanePairing, nil
	case ALPNConsensus:
		return PlaneConsensus, nil
	case ALPNContent:
		return PlaneContent, nil
	default:
		return "", ErrInvalidALPNOffer
	}
}

// ALPN returns the exact protocol identifier for a valid plane.
func (plane Plane) ALPN() (string, error) {
	switch plane {
	case PlanePairing:
		return ALPNPairing, nil
	case PlaneConsensus:
		return ALPNConsensus, nil
	case PlaneContent:
		return ALPNContent, nil
	default:
		return "", ErrInvalidALPNOffer
	}
}
