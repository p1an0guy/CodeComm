package crypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"

	"github.com/ijonahch/codecomm/internal/codec"
)

func TestGenerateEd25519KeyPairRoundTripAndNoAliasing(t *testing.T) {
	publicKey, privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}
	if len(publicKey) != Ed25519PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(publicKey), Ed25519PublicKeySize)
	}
	if len(privateKey) != Ed25519PrivateKeySize {
		t.Fatalf("private key length = %d, want %d", len(privateKey), Ed25519PrivateKeySize)
	}
	if !bytes.Equal(publicKey, privateKey[ed25519.SeedSize:]) {
		t.Fatal("generated public key does not match private key")
	}

	privatePublicByte := privateKey[ed25519.SeedSize]
	publicKey[0] ^= 0xff
	if privateKey[ed25519.SeedSize] != privatePublicByte {
		t.Fatal("generated public and private keys share backing storage")
	}

	publicKey[0] ^= 0xff
	signature, err := SignEd25519(privateKey, codec.SignatureEventOrigin, []byte(`{"id":"one"}`))
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if err := VerifyEd25519(
		publicKey,
		codec.SignatureEventOrigin,
		[]byte(`{"id":"one"}`),
		signature,
	); err != nil {
		t.Fatalf("VerifyEd25519() error = %v", err)
	}
}

func TestGenerateEd25519KeyPairReportsEntropyFailure(t *testing.T) {
	injected := errors.New("injected entropy failure")
	publicKey, privateKey, err := generateEd25519KeyPair(failingReader{err: injected})
	if publicKey != nil || privateKey != nil {
		t.Fatalf("generateEd25519KeyPair() keys = %x, %x; want nil", publicKey, privateKey)
	}
	if !errors.Is(err, ErrEntropy) {
		t.Fatalf("generateEd25519KeyPair() error = %v, want ErrEntropy", err)
	}
	if !errors.Is(err, injected) {
		t.Fatalf("generateEd25519KeyPair() error = %v, want injected cause", err)
	}
}

func TestSignEd25519UsesExactCodecSignedInput(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	signedBytes := []byte(`{"kind":"task.created"}`)

	got, err := SignEd25519(privateKey, codec.SignatureEventOrigin, signedBytes)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	input, err := codec.BuildSignedInput(codec.SignatureEventOrigin, signedBytes)
	if err != nil {
		t.Fatalf("codec.BuildSignedInput() error = %v", err)
	}
	want := ed25519.Sign(privateKey, input)
	if !bytes.Equal(got, want) {
		t.Fatalf("SignEd25519() = %x, want %x", got, want)
	}
}

func TestEd25519PublicKeyFromPrivateKey(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}
	got, err := Ed25519PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Ed25519PublicKeyFromPrivateKey() error = %v", err)
	}
	if !bytes.Equal(got, publicKey) {
		t.Fatalf("Ed25519PublicKeyFromPrivateKey() = %x, want %x", got, publicKey)
	}
	privateKey[ed25519.SeedSize] ^= 0xff
	if bytes.Equal(got, privateKey[ed25519.SeedSize:]) {
		t.Fatal("Ed25519PublicKeyFromPrivateKey() result aliases its input")
	}
}

func TestEd25519PublicKeyFromPrivateKeyRejectsMalformedKey(t *testing.T) {
	t.Parallel()

	for _, privateKey := range [][]byte{
		nil,
		make([]byte, Ed25519PrivateKeySize-1),
		make([]byte, Ed25519PrivateKeySize),
	} {
		if len(privateKey) == Ed25519PrivateKeySize {
			privateKey[len(privateKey)-1] = 1
		}
		publicKey, err := Ed25519PublicKeyFromPrivateKey(privateKey)
		if publicKey != nil {
			t.Fatalf("Ed25519PublicKeyFromPrivateKey() = %x after error, want nil", publicKey)
		}
		if !errors.Is(err, ErrInvalidEd25519PrivateKey) {
			t.Fatalf(
				"Ed25519PublicKeyFromPrivateKey(%d bytes) error = %v, want %v",
				len(privateKey),
				err,
				ErrInvalidEd25519PrivateKey,
			)
		}
	}
}

func TestEd25519RejectsMalformedKeysAndSignatures(t *testing.T) {
	publicKey, privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}
	signedBytes := []byte(`{"id":"one"}`)
	signature, err := SignEd25519(privateKey, codec.SignatureGenesis, signedBytes)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}

	for _, size := range []int{0, Ed25519PrivateKeySize - 1, Ed25519PrivateKeySize + 1} {
		_, err := SignEd25519(make([]byte, size), codec.SignatureGenesis, signedBytes)
		if !errors.Is(err, ErrInvalidEd25519PrivateKey) {
			t.Errorf("SignEd25519(private key size %d) error = %v, want ErrInvalidEd25519PrivateKey", size, err)
		}
	}

	inconsistentPrivateKey := bytes.Clone(privateKey)
	inconsistentPrivateKey[Ed25519PrivateKeySize-1] ^= 0xff
	if _, err := SignEd25519(
		inconsistentPrivateKey,
		codec.SignatureGenesis,
		signedBytes,
	); !errors.Is(err, ErrInvalidEd25519PrivateKey) {
		t.Errorf("SignEd25519(inconsistent private key) error = %v, want ErrInvalidEd25519PrivateKey", err)
	}

	for _, size := range []int{0, Ed25519PublicKeySize - 1, Ed25519PublicKeySize + 1} {
		err := VerifyEd25519(make([]byte, size), codec.SignatureGenesis, signedBytes, signature)
		if !errors.Is(err, ErrInvalidEd25519PublicKey) {
			t.Errorf("VerifyEd25519(public key size %d) error = %v, want ErrInvalidEd25519PublicKey", size, err)
		}
	}
	for _, size := range []int{0, Ed25519SignatureSize - 1, Ed25519SignatureSize + 1} {
		err := VerifyEd25519(publicKey, codec.SignatureGenesis, signedBytes, make([]byte, size))
		if !errors.Is(err, ErrInvalidEd25519Signature) {
			t.Errorf("VerifyEd25519(signature size %d) error = %v, want ErrInvalidEd25519Signature", size, err)
		}
	}
}

func TestVerifyEd25519RejectsWrongLabelObjectKeyAndSignature(t *testing.T) {
	publicKey, privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}
	otherPublicKey, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() second error = %v", err)
	}
	signedBytes := []byte(`{"id":"one"}`)
	signature, err := SignEd25519(privateKey, codec.SignatureGenesis, signedBytes)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}

	tests := []struct {
		name        string
		publicKey   []byte
		label       codec.SignatureLabel
		signedBytes []byte
		signature   []byte
	}{
		{
			name:        "wrong label",
			publicKey:   publicKey,
			label:       codec.SignatureDiscovery,
			signedBytes: signedBytes,
			signature:   signature,
		},
		{
			name:        "wrong object",
			publicKey:   publicKey,
			label:       codec.SignatureGenesis,
			signedBytes: []byte(`{"id":"two"}`),
			signature:   signature,
		},
		{
			name:        "wrong key",
			publicKey:   otherPublicKey,
			label:       codec.SignatureGenesis,
			signedBytes: signedBytes,
			signature:   signature,
		},
		{
			name:        "changed signature",
			publicKey:   publicKey,
			label:       codec.SignatureGenesis,
			signedBytes: signedBytes,
			signature:   changedCopy(signature),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := VerifyEd25519(
				test.publicKey,
				test.label,
				test.signedBytes,
				test.signature,
			)
			if !errors.Is(err, ErrSignatureVerification) {
				t.Fatalf("VerifyEd25519() error = %v, want ErrSignatureVerification", err)
			}
		})
	}
}

func TestEd25519RejectsUnknownSignatureLabel(t *testing.T) {
	publicKey, privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}
	label := codec.SignatureLabel("codecomm/v1/not-a-signature-label")

	signature, err := SignEd25519(privateKey, label, []byte("{}"))
	if signature != nil {
		t.Fatalf("SignEd25519() signature = %x, want nil", signature)
	}
	if !errors.Is(err, codec.ErrInvalidSignatureLabel) {
		t.Fatalf("SignEd25519() error = %v, want codec.ErrInvalidSignatureLabel", err)
	}

	err = VerifyEd25519(publicKey, label, []byte("{}"), make([]byte, Ed25519SignatureSize))
	if !errors.Is(err, codec.ErrInvalidSignatureLabel) {
		t.Fatalf("VerifyEd25519() error = %v, want codec.ErrInvalidSignatureLabel", err)
	}
}

func TestSignEd25519DoesNotAliasOrMutateInputs(t *testing.T) {
	publicKey, privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}
	originalPrivateKey := bytes.Clone(privateKey)
	signedBytes := []byte(`{"id":"one"}`)
	originalSignedBytes := bytes.Clone(signedBytes)

	signature, err := SignEd25519(privateKey, codec.SignatureGenesis, signedBytes)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if !bytes.Equal(privateKey, originalPrivateKey) {
		t.Fatal("SignEd25519() mutated private key")
	}
	if !bytes.Equal(signedBytes, originalSignedBytes) {
		t.Fatal("SignEd25519() mutated signed bytes")
	}

	signedBytes[0] ^= 0xff
	privateKey[0] ^= 0xff
	if err := VerifyEd25519(
		publicKey,
		codec.SignatureGenesis,
		originalSignedBytes,
		signature,
	); err != nil {
		t.Fatalf("signature aliases an input: VerifyEd25519() error = %v", err)
	}
}

func TestSumSHA256(t *testing.T) {
	input := []byte("abc")
	got := SumSHA256(input)
	want := SHA256Digest{
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	}
	if got != want {
		t.Fatalf("SumSHA256(%q) = %x, want %x", input, got, want)
	}

	input[0] = 'z'
	if got != want {
		t.Fatal("SumSHA256() result aliases its input")
	}
	if SumSHA256([]byte("abd")) == got {
		t.Fatal("SumSHA256() did not change for changed input")
	}
}

type failingReader struct {
	err error
}

func (reader failingReader) Read([]byte) (int, error) {
	return 0, reader.err
}

func changedCopy(value []byte) []byte {
	result := bytes.Clone(value)
	result[len(result)-1] ^= 0xff
	return result
}

var _ io.Reader = failingReader{}
