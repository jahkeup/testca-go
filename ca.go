package testca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"
)

var DefaultRootTemplate = x509.Certificate{
	SerialNumber: big.NewInt(1),
	Subject: pkix.Name{
		Organization: []string{"TestCA, security through (test-env) insecurity!"},
		CommonName:   "testca.test",
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().Add(time.Hour),
	KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	BasicConstraintsValid: true,
	IsCA:                  true,
}

type TestCA[PUB, PRIV any] struct {
	RootPublicKey PUB
	RootPrivateKey PRIV

	RootTemplate *x509.Certificate
	rootCert []byte
	rootCertificate *x509.Certificate

	Rand io.Reader
}

func (t *TestCA[PUB, PRIV]) buildRoot(template *x509.Certificate) (*x509.Certificate, error) {
	if c := t.rootCertificate; c != nil {
		return c, nil
	}

	if template == nil {
		template = t.RootTemplate
	}

	if template == nil {
		fromDefault := DefaultRootTemplate
		template = &fromDefault
	}

	// ensure IsCA to be a CA :)
	template.IsCA = true


	if r := t.Rand; r == nil {
		t.Rand = rand.Reader
	}

	cert, err := x509.CreateCertificate(t.Rand, template, template, t.RootPublicKey, t.RootPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("self-sign: %w", err)
	}

	certificate, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("parse self: %w", err)
	}

	t.rootCert, t.rootCertificate = cert, certificate

	return t.rootCertificate, nil
}

func (t *TestCA[PUB, PRIV]) RootCert() *x509.Certificate {
	c, _ := t.buildRoot(nil)

	return c
}

func (t *TestCA[PUB, PRIV]) RootCertPEM() pem.Block {
	_, _ = t.buildRoot(nil)

	return pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   t.rootCert,
	}
}

func (t *TestCA[PUB, PRIV]) CreateCertificate(template *x509.Certificate, pub PUB) (*pem.Block, error) {
	_, err := t.buildRoot(nil)
	if err != nil {
		return nil, err
	}

	cert, err := x509.CreateCertificate(t.Rand, template, t.rootCertificate, pub, t.RootPrivateKey)
	if err != nil {
		return nil, err
	}

	return &pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   cert,
	}, nil
}
