package testca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type ECDSA = TestCA[*ecdsa.PublicKey, *ecdsa.PrivateKey]

func CreateECDSA(ca *ECDSA, template x509.Certificate) (*Cert[*ecdsa.PrivateKey], error) {
	pk := GeneratePrivateKeyECDSA()
	if pk == nil {
		return nil, errors.New("generate key: failed")
	}

	block, cert, err := ca.StrictCreateCertificate(&template, &pk.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	helperCert := Cert[*ecdsa.PrivateKey]{
		Certificate: cert,
		PEM:         block,
		PrivateKey:  pk,
		Template:    &template,
	}

	return &helperCert, nil
}

type Cert[PRIV crypto.Signer] struct {
	Certificate *x509.Certificate
	PEM         *pem.Block
	PrivateKey  PRIV
	Template    *x509.Certificate
}

type RootCertProvider interface {
	RootCert() *x509.Certificate
}

func NewCertPool(caProviders ...RootCertProvider) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, ca := range caProviders {
		pool.AddCert(ca.RootCert())
	}
	return pool
}
