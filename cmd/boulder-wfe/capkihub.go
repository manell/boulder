package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/letsencrypt/boulder/core"
	pkihubsigner "github.com/safelayer/pkihub/ca"
	"github.com/safelayer/pkihub/certpolicy"
	"golang.org/x/net/context"
)

type certificateStorage interface {
	AddCertificate(context.Context, []byte, int64) (string, error)
}

type PKIHubCA struct {
	SA certificateStorage
}

func NewPKIHubCA(sa certificateStorage) *PKIHubCA {
	return &PKIHubCA{SA: sa}
}

/*

type Certificate struct {
	RegistrationID int64 `db:"registrationID"`

	Serial  string    `db:"serial"`
	Digest  string    `db:"digest"`
	DER     []byte    `db:"der"`
	Issued  time.Time `db:"issued"`
	Expires time.Time `db:"expires"`
*/

func (ca *PKIHubCA) IssueCertificate(ctx context.Context, csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	rootPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return core.Certificate{}, err
	}

	rootTemplate := &x509.Certificate{}
	serialNumberLimit := (&big.Int{}).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return core.Certificate{}, err
	}
	rootTemplate.SerialNumber = serialNumber
	caCert, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPrivate.Public(), rootPrivate)
	if err != nil {
		return core.Certificate{}, err
	}

	rootCert, err := x509.ParseCertificate(caCert)
	if err != nil {
		return core.Certificate{}, err
	}

	policy := &certpolicy.CertificationPolicyBody{
		Subject: &certpolicy.PolicySubject{
			CommonName: &certpolicy.StringParam{
				Override: "cnOverride",
			},
		},
		SubjectAltName: &certpolicy.StringListParam{
			Default: []string{},
		},
		KeyUsage: &certpolicy.StringListParam{
			Override: []string{"keyEncipherment", "digitalSignature"},
		},
		ExtendedKeyUsage: &certpolicy.StringListParam{
			Override: []string{"serverAuth", "clientAuth"},
		},
	}

	signer, err := pkihubsigner.NewSigner(rootCert, rootPrivate, policy)
	if err != nil {
		return core.Certificate{}, err
	}
	cert, _, err := signer.Sign(&pkihubsigner.SignRequest{
		CSR: csr.Raw,
		CertificateRequestValues: &pkihubsigner.CertificateRequestValues{
			Subject: pkihubsigner.Subject{},
		},
	})
	if err != nil {
		return core.Certificate{}, err
	}

	/*template := x509.Certificate{}

	template.Subject = csr.Subject
	template.DNSNames = csr.DNSNames

	template.PublicKey = csr.PublicKey
	template.PublicKeyAlgorithm = csr.PublicKeyAlgorithm

	template.SerialNumber = serialNumber

	cert, err := x509.CreateCertificate(rand.Reader, &template, rootCert, rootPrivate.Public(), rootPrivate)
	if err != nil {
		return core.Certificate{}, err
	}*/

	certificate := core.Certificate{
		RegistrationID: regID,
		Digest:         "demo",
		DER:            cert,
		Issued:         time.Now(),
		Expires:        time.Now().Add(time.Second * 40000),
	}

	//_, err = ca.SA.AddCertificate(ctx, cert, regID)
	if err != nil {
		return core.Certificate{}, err
	}

	return certificate, nil
}

func (ca *PKIHubCA) GenerateOCSP(ctx context.Context, ocspReq core.OCSPSigningRequest) ([]byte, error) {
	return nil, nil
}
