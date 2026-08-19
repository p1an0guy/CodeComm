package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain/device"
)

func TestAcquireSettledNonvoterExcludesConfiguredServer(t *testing.T) {
	node, _, localDeviceID := openApplyAtGenerationTestNode(t)
	if release, err := node.AcquireSettledNonvoter(
		context.Background(),
		localDeviceID,
	); !errors.Is(err, ErrPairingSubjectConfigured) || release != nil {
		t.Fatalf(
			"AcquireSettledNonvoter(configured) = (non-nil %t, %v)",
			release != nil,
			err,
		)
	}

	otherKey := ed25519.NewKeyFromSeed(
		bytes.Repeat([]byte{0x7d}, ed25519.SeedSize),
	)
	otherDeviceID, err := device.DeriveID(
		otherKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	release, err := node.AcquireSettledNonvoter(
		context.Background(),
		otherDeviceID,
	)
	if err != nil || release == nil {
		t.Fatalf(
			"AcquireSettledNonvoter(other) = (non-nil %t, %v)",
			release != nil,
			err,
		)
	}
	release()
	release()
	second, err := node.AcquireSettledNonvoter(
		context.Background(),
		otherDeviceID,
	)
	if err != nil || second == nil {
		t.Fatalf(
			"AcquireSettledNonvoter(after release) = (non-nil %t, %v)",
			second != nil,
			err,
		)
	}
	second()
}
