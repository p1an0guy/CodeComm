package chain_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/ijonahch/codecomm/internal/chain"
)

func filledDigest(value byte) chain.Digest {
	var digest chain.Digest
	for index := range digest {
		digest[index] = value
	}
	return digest
}

func proposalDigest(proposal []byte) chain.Digest {
	return chain.Digest(sha256.Sum256(proposal))
}

func manualDomainDigest(label string, parts ...[]byte) chain.Digest {
	digester := sha256.New()
	writeTestBytes(digester, []byte(label))
	writeTestBytes(digester, []byte{0})
	for _, part := range parts {
		writeTestBytes(digester, part)
	}
	return sumTestDigest(digester)
}

func testUint64(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}

func writeTestBytes(digester hash.Hash, value []byte) {
	_, _ = digester.Write(value)
}

func sumTestDigest(digester hash.Hash) chain.Digest {
	var digest chain.Digest
	copy(digest[:], digester.Sum(nil))
	return digest
}

func assertDigest(t *testing.T, label string, got chain.Digest, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil || len(want) != sha256.Size {
		t.Fatalf("%s invalid test vector %q: %v", label, wantHex, err)
	}
	if string(got[:]) != string(want) {
		t.Errorf("%s = %x, want %x", label, got, want)
	}
}
