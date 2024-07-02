package testca_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/jahkeup/testca-go"
)

func TestNewECDSA(t *testing.T) {
	ca, err := testca.NewECDSA()
	if err != nil {
		t.Fatalf("must create testca, but errored: %v", err)
	}

	pk := testca.GeneratePrivateKeyECDSA()
	if pk == nil {
		t.Fatal("must get test pk, but have nil")
	}
	pemBlock, cert, err := ca.CreateCertificate(&x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"other.testca.test", "new-ecdsa.testca.test"},
	}, &pk.PublicKey)

	if err != nil {
		t.Fatalf("expected certificate ok, but errored: %v", err)
	}

	if pemBlock == nil || cert == nil {
		t.Fatal("expected certificate returned, but have none (or some)")
	}

	chains, err := cert.Verify(x509.VerifyOptions{
		DNSName:                   "new-ecdsa.testca.test",
		Roots:                     testca.SharedPool(),
		CurrentTime:               time.Now(),
		KeyUsages:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	if err != nil {
		t.Fatalf("expected to verify cert, but failed: %v", err)
	}

	if len(chains) == 0 {
		t.Fatal("expected a matching chain for cert, but none found")
	}

	t.Logf("verified chains: %#v", chains)
}
