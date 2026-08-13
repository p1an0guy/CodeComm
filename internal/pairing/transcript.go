package pairing

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ExporterLabel = "EXPORTER-CodeComm-Pairing-v1"
	ExporterSize  = 32
	ProofSize     = sha256.Size

	pairingTranscriptLabel = "codecomm/v1/pairing-transcript"
	inviteProofLabel       = "codecomm/v1/invite-proof"
	sasTranscriptLabel     = "codecomm/v1/sas-transcript"
)

var ErrInvalidTranscript = errors.New("pairing: invalid transcript input")

func buildTranscriptHash(
	exporter []byte,
	inviterIdentityPublicKey []byte,
	joinerIdentityPublicKey []byte,
	inviteDigest [sha256.Size]byte,
	canonicalRequestCore []byte,
) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if len(exporter) != ExporterSize ||
		len(inviterIdentityPublicKey) != 32 ||
		len(joinerIdentityPublicKey) != 32 ||
		len(canonicalRequestCore) == 0 ||
		len(canonicalRequestCore) > MaxPairingMessageBytes {
		return zero, ErrInvalidTranscript
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(pairingTranscriptLabel))
	_, _ = hash.Write([]byte{0})
	writeLengthFramed(hash, exporter)
	writeLengthFramed(hash, inviterIdentityPublicKey)
	writeLengthFramed(hash, joinerIdentityPublicKey)
	writeLengthFramed(hash, inviteDigest[:])
	writeLengthFramed(hash, canonicalRequestCore)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeLengthFramed(writer byteWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func inviteProof(secret [InviteSecretSize]byte, transcriptHash [sha256.Size]byte) [ProofSize]byte {
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write([]byte(inviteProofLabel))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(transcriptHash[:])
	var proof [ProofSize]byte
	copy(proof[:], mac.Sum(nil))
	return proof
}

func proofEqual(left, right [ProofSize]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func renderSAS(transcriptHash [sha256.Size]byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(sasTranscriptLabel))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(transcriptHash[:])
	digest := hash.Sum(nil)
	return fmt.Sprintf(
		"%04d %04d %04d %04d %04d",
		binary.BigEndian.Uint16(digest[0:2])%10_000,
		binary.BigEndian.Uint16(digest[2:4])%10_000,
		binary.BigEndian.Uint16(digest[4:6])%10_000,
		binary.BigEndian.Uint16(digest[6:8])%10_000,
		binary.BigEndian.Uint16(digest[8:10])%10_000,
	)
}
