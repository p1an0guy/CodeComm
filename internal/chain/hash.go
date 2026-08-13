package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

const (
	genesisDigestLabel         = "codecomm/v1/genesis-digest"
	eventChainLabel            = "codecomm/v1/chain"
	resultChainLabel           = "codecomm/v1/result-chain"
	projectionAccumulatorLabel = "codecomm/v1/projection-accumulator"
	projectionRowLabel         = "codecomm/v1/projection-row"
	projectionTableLabel       = "codecomm/v1/projection-table"
	projectionStateLabel       = "codecomm/v1/projection-state"
)

// GenesisDigest commits the complete canonical signed genesis object.
func GenesisDigest(canonicalCompleteGenesis []byte) (Digest, error) {
	if err := validateCanonicalObject(
		"genesis",
		canonicalCompleteGenesis,
	); err != nil {
		return Digest{}, err
	}
	return digestDomain(genesisDigestLabel, canonicalCompleteGenesis), nil
}

// EventSeed computes the event-chain head at a generation boundary.
func EventSeed(boundary Boundary) (Digest, error) {
	if err := validateBoundary(boundary); err != nil {
		return Digest{}, err
	}
	return boundarySeed(eventChainLabel, boundary), nil
}

// ResultSeed computes the result-chain head at a generation boundary.
func ResultSeed(boundary Boundary) (Digest, error) {
	if err := validateBoundary(boundary); err != nil {
		return Digest{}, err
	}
	return boundarySeed(resultChainLabel, boundary), nil
}

// AppendEvent extends the event chain with an accepted canonical signed event.
func AppendEvent(previous Digest, canonical []byte) (Digest, error) {
	if err := validateCanonicalObject("signed event", canonical); err != nil {
		return Digest{}, err
	}
	return digestDomain(eventChainLabel, previous[:], canonical), nil
}

// AccumulatorSeedInitial commits generation 0's genesis and initial full-state
// digest.
func AccumulatorSeedInitial(genesis, state Digest) Digest {
	return digestDomain(projectionAccumulatorLabel, genesis[:], state[:])
}

// AccumulatorSeedSuccessor carries the predecessor accumulator into a
// successor generation after its deterministic state transform.
func AccumulatorSeedSuccessor(previous, genesis, state Digest) Digest {
	return digestDomain(
		projectionAccumulatorLabel,
		previous[:],
		genesis[:],
		state[:],
	)
}

func validateBoundary(boundary Boundary) error {
	if boundary.Generation > maxSafeInteger ||
		boundary.ChainIndex > maxSafeInteger ||
		boundary.ResultIndex > maxSafeInteger {
		return fmt.Errorf("%w: value exceeds exact-integer range", ErrInvalidBoundary)
	}
	if boundary.ChainIndex > boundary.ResultIndex {
		return fmt.Errorf(
			"%w: chain index %d exceeds result index %d",
			ErrInvalidBoundary,
			boundary.ChainIndex,
			boundary.ResultIndex,
		)
	}
	if boundary.Generation == 0 &&
		(boundary.ChainIndex != 0 ||
			boundary.ResultIndex != 0 ||
			boundary.ChainHash != (Digest{}) ||
			boundary.ResultHash != (Digest{})) {
		return fmt.Errorf("%w: generation 0 has predecessor state", ErrInvalidBoundary)
	}
	if boundary.Generation > 0 &&
		(boundary.ChainHash == (Digest{}) ||
			boundary.ResultHash == (Digest{})) {
		return fmt.Errorf(
			"%w: successor has a zero predecessor head",
			ErrInvalidBoundary,
		)
	}
	return nil
}

func boundarySeed(label string, boundary Boundary) Digest {
	if boundary.Generation == 0 {
		return digestDomain(label, boundary.Genesis[:])
	}

	return digestDomain(
		label,
		boundary.Genesis[:],
		uint64Bytes(boundary.Generation),
		uint64Bytes(boundary.ChainIndex),
		boundary.ChainHash[:],
		uint64Bytes(boundary.ResultIndex),
		boundary.ResultHash[:],
	)
}

func digestDomain(label string, parts ...[]byte) Digest {
	digester := sha256.New()
	writeBytes(digester, []byte(label))
	writeBytes(digester, []byte{0})
	for _, part := range parts {
		writeBytes(digester, part)
	}
	var digest Digest
	copy(digest[:], digester.Sum(nil))
	return digest
}

func uint64Bytes(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}

func writeUint64(digester hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeBytes(digester, encoded[:])
}

func writeBytes(digester hash.Hash, value []byte) {
	_, _ = digester.Write(value)
}
