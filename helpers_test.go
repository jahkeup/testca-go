package testca_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/jahkeup/testca-go"
)

func TestECDSACertificate(t *testing.T) {
	ca, err := testca.NewECDSA()
	if err != nil {
		t.Fatalf("must create testca, but errored: %v", err)
	}

	cert, err := testca.CreateECDSA(ca, x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"other.testca.test", "ecdsa-cert.testca.test"},
	})

	if err != nil {
		t.Fatalf("must create cert, but errored: %v", err)
	}

	if cert == nil {
		t.Fatal("must create cert, but none returned")
	}

	_, err = cert.Certificate.Verify(x509.VerifyOptions{
		DNSName:                   "ecdsa-cert.testca.test",
		Roots:                     testca.NewCertPool(ca),
		CurrentTime:               time.Now(),
	})

	if err != nil {
		t.Fatal("cert must verify by CA cert, but failed to verify")
	}
}
