// package testca provides a basic suitable-for-testing-ONLY certificate
// authority.
//
// The implementation here tries to make as little assumption about your use
// case and aims to provide helpful extensions to stdlib types first and
// foremost. Certificate details and private key management are (mostly) taken
// care of by users of this small test support library.
//
// Please see also relevant documentation covering X.509, X.520, ASN.1:
//
// X.509 (PKI and directory types)
//
// - X.509 recommendation: https://www.itu.int/rec/T-REC-X.509
// - X.509 rfc standard: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
//
// X.520 (ISO/IEC 9594-6:2020, ITU-T X.520-201910) (Directory Types)
//
// - X.520 recommendation: https://www.itu.int/rec/T-REC-X.520
//
// DN (Directory's distinguished name(s)):
//
// - X.520 recommendation: https://www.itu.int/rec/T-REC-X.520
//   - section 6.2.8
//
// - rfc standard (old): https://datatracker.ietf.org/doc/html/rfc1779 (obsolete)
// - rfc standard: https://datatracker.ietf.org/doc/html/rfc2253
package testca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"
	"time"
)

const (
	// KeyUsageTestCA is the KeyUsage used in self-signing by the library.
	KeyUsageTestCA = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
)

const (
	// generateCAValidityPeriod specifies the validity period for the generated
	// TestCA root certifcate.
	generateCAValidityPeriod = 72 * time.Hour
	// generateNotBeforeAgo specifies an offset used to calculate NotBefore
	// (which shifts the validity period back a little bit).
	generateNotBeforeAgo = 5 * time.Minute
	// certificateValidityPeriod specfies the validity period of CA signed
	// certficates.
	certificateValidityPeriod = 1 * time.Hour
)

// testCASerialCounter is a shared counter used to globally increment generated
// certificates' serial number.
var testCASerialCounter atomic.Int64

// testCAPool is a pool of all the TestCA certificates created.
var testCAPool = x509.NewCertPool()

// Pool returns a copy of the TestCA shared pool.
func SharedPool() *x509.CertPool {
	return testCAPool.Clone()
}

func addTestCAPool(cert *x509.Certificate) {
	testCAPool.AddCert(cert)
}

// DefaultRootTemplate provides the template x509 "certificate" used to generate
// new TestCA root certificates (when not configured, see TestCA).
func DefaultRootTemplate() *x509.Certificate {
	var vendedCopy x509.Certificate = defaultRootTemplateValue
	// TODO: return deepcopy
	return &vendedCopy
}

// SetDefaultRootTemplate configures the given certificate to use as the root CA
// template.
func SetDefaultRootTemplate(cert x509.Certificate) {
	if cert.IsCA != true {
		panic("IsCA must be configured")
	}

	if cert.KeyUsage == 0 {
		cert.KeyUsage = KeyUsageTestCA
	}

	if cert.SerialNumber == nil || cert.SerialNumber.Int64() == 0 {
		cert.SerialNumber = big.NewInt(testCASerialCounter.Add(1))
	}

	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
		cert.NotBefore = time.Now().Add(-1 * generateNotBeforeAgo)
		cert.NotAfter = cert.NotBefore.Add(generateCAValidityPeriod + generateNotBeforeAgo)
	}

	defaultRootTemplateValue = cert
}

func init() {
	SetDefaultRootTemplate(x509.Certificate{
		Subject: pkix.Name{
			Country:            []string{"TT"}, // trinidad
			Organization:       []string{"TestCA, security through (test-env) insecurity!"},
			OrganizationalUnit: []string{"Software"},
			Locality:           []string{"Softwhere"},
			Province:           []string{"Hardwhere"},
			StreetAddress:      []string{"101 0th St SW"},
			PostalCode:         []string{"01010"},
			CommonName:         "testca.test",
		},

		KeyUsage: KeyUsageTestCA,

		BasicConstraintsValid: true,
		IsCA:                  true,
	})
}

// defaultRootTemplateValue is the shared value behind DefaultRootTemplate.
var defaultRootTemplateValue x509.Certificate

// TestCA provides a minimal implementation of a certificate authority in order
// to manage certificates. The implementation aims to expose the majority of the
// PKI so that different use cases are able to share the same support code.
//
// A valid TestCA has, at a minimum, its RootPublicKey and RootPrivateKey fields
// given. DefaultRootTemplate vends the CA template if none is given in
// RootTemplate.
type TestCA[PUB any, PRIV crypto.Signer] struct {
	RootPublicKey  PUB
	RootPrivateKey PRIV

	RootTemplate    *x509.Certificate
	rootCert        []byte
	rootCertificate *x509.Certificate

	Rand io.Reader

	serialCounter *atomic.Int64
}

// NewECDSA constructs a TestCA using ECDSA private key. Materials are available
// through the TestCA returned.
func NewECDSA() (*TestCA[*ecdsa.PublicKey, *ecdsa.PrivateKey], error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate testca: %w", err)
	}

	return &TestCA[*ecdsa.PublicKey, *ecdsa.PrivateKey]{
		RootPublicKey:  &privateKey.PublicKey,
		RootPrivateKey: privateKey,
	}, nil
}

// GeneratePrivateKeyECDSA generates a new ECDSA private key. Treat is as an
// opaque private key - *some* private key that's ok to test with.
func GeneratePrivateKeyECDSA() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	return priv
}

// buildRoot internally ensures the root CA has been initialized and performs
// any required setup.
func (t *TestCA[PUB, PRIV]) buildRoot(template *x509.Certificate) (*x509.Certificate, error) {
	if t.serialCounter == nil {
		t.serialCounter = &testCASerialCounter
	}
	if r := t.Rand; r == nil {
		t.Rand = rand.Reader
	}

	if c := t.rootCertificate; c != nil {
		return c, nil
	}

	if template == nil {
		template = t.RootTemplate
	}

	if template == nil {
		template = DefaultRootTemplate()
	}

	// ensure IsCA to be a CA :)
	template.IsCA = true

	template.SerialNumber = t.IncrementedSerial()

	selfAsParent := template // for clarity; we're self-signing!
	cert, err := x509.CreateCertificate(t.Rand, template, selfAsParent, t.RootPublicKey, t.RootPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("self-sign: %w", err)
	}

	certificate, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("parse self: %w", err)
	}

	t.rootCert, t.rootCertificate = cert, certificate

	// add generated certificate to shared pool
	addTestCAPool(t.rootCertificate)

	return t.rootCertificate, nil
}

// RootCert provides the X.509 certificate of the TestCA.
func (t *TestCA[PUB, PRIV]) RootCert() *x509.Certificate {
	c, _ := t.buildRoot(nil)

	rootCert := *c

	return &rootCert
}

// RootCertPEM provides the X.509 certificate of the TestCA as a ready-to-encode
// PEM block.
func (t *TestCA[PUB, PRIV]) RootCertPEM() pem.Block {
	_, _ = t.buildRoot(nil)

	return pem.Block{
		Type:  "CERTIFICATE",
		Bytes: t.rootCert[:],
	}
}

// CreateCertificate creates a TestCA signed certificate for the given input
// template. The public key provided is assumed to be supported for
// CreateCertificate use (see https://pkg.go.dev/crypto/x509#CreateCertificate
// for list).
func (t *TestCA[PUB, PRIV]) CreateCertificate(template *x509.Certificate, pub crypto.PublicKey) (*pem.Block, *x509.Certificate, error) {
	_, err := t.buildRoot(nil)
	if err != nil {
		return nil, nil, err
	}

	if template.SerialNumber == nil || template.SerialNumber.Int64() == 0 {
		template.SerialNumber = t.IncrementedSerial()
	}

	if template.Issuer.String() == (pkix.Name{}).String() {
		if rootTemplate := t.RootTemplate; rootTemplate != nil {
			// configure issuer from root
			template.Issuer = rootTemplate.Issuer
		}
	}

	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-1 * generateNotBeforeAgo)
	}

	if template.NotAfter.IsZero() {
		if notBefore := template.NotBefore; !notBefore.IsZero() {
			template.NotAfter = notBefore.Add(certificateValidityPeriod)
		} else {
			template.NotAfter = time.Now().Add(certificateValidityPeriod)
		}
	}

	certDER, err := x509.CreateCertificate(t.Rand, template, t.rootCertificate, pub, t.RootPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return certPEMBlock, nil, fmt.Errorf("parse generated cert: %w", err)
	}

	return certPEMBlock, cert, nil
}

// StrictCreateCertificate is a strict variant requiring public key provided to
// match the type used by the TestCA.
func (t *TestCA[PUB, PRIV]) StrictCreateCertificate(template *x509.Certificate, pub PUB) (*pem.Block, *x509.Certificate, error) {
	return t.CreateCertificate(template, pub)
}

// IncrementedSerial returns the next serial number for issuing a certificate in
// this CA.
func (t *TestCA[PUB, PRIV]) IncrementedSerial() *big.Int {
	// if none is configured, an internal serial counter is created _per-ca_.
	// The constructor helpers (eg: NewECDSA) use a shared serial counter.
	if t.serialCounter == nil {
		t.serialCounter = &atomic.Int64{}
	}

	return big.NewInt(t.serialCounter.Add(1))
}
