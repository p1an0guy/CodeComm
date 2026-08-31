package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestClearBootstrapTLSConfigZeroesOwnedCertificate(t *testing.T) {
	t.Parallel()

	der := bytes.Repeat([]byte{0x41}, 32)
	privateKey := ed25519.PrivateKey(bytes.Repeat(
		[]byte{0x42},
		ed25519.PrivateKeySize,
	))
	ocsp := bytes.Repeat([]byte{0x43}, 16)
	sct := bytes.Repeat([]byte{0x44}, 16)
	config := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate:                 [][]byte{der},
			PrivateKey:                  privateKey,
			OCSPStaple:                  ocsp,
			SignedCertificateTimestamps: [][]byte{sct},
		}},
		GetCertificate: func(
			*tls.ClientHelloInfo,
		) (*tls.Certificate, error) {
			return nil, nil
		},
		GetClientCertificate: func(
			*tls.CertificateRequestInfo,
		) (*tls.Certificate, error) {
			return nil, nil
		},
		VerifyPeerCertificate: func(
			[][]byte,
			[][]*x509.Certificate,
		) error {
			return nil
		},
		VerifyConnection: func(tls.ConnectionState) error {
			return nil
		},
	}
	clearBootstrapTLSConfig(config)
	if len(config.Certificates) != 0 ||
		config.GetCertificate != nil ||
		config.GetClientCertificate != nil ||
		config.VerifyPeerCertificate != nil ||
		config.VerifyConnection != nil ||
		!allZeroTransportBytes(der) ||
		!allZeroTransportBytes(privateKey) ||
		!allZeroTransportBytes(ocsp) ||
		!allZeroTransportBytes(sct) {
		t.Fatal("bootstrap TLS configuration retained owned key material")
	}
}

func allZeroTransportBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
