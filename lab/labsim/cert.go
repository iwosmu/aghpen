package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/iwosmu/aghpen/lab/labcfg"
)

func newKey(kind string) (crypto.Signer, error) {
	if kind == "rsa2048" {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

// makeCert creates the certificate a TLS spec asks for. Dates are relative
// to now, so an "expired" certificate is always expired and a "valid" one is
// always valid, whenever the lab starts.
func makeCert(spec *labcfg.TLS, now time.Time) (*tls.Certificate, error) {
	day := 24 * time.Hour
	leafKey, err := newKey(spec.Key)
	if err != nil {
		return nil, err
	}
	subject := pkix.Name{CommonName: spec.CN}
	if spec.Org != "" {
		subject.Organization = []string{spec.Org}
	}
	leaf := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               subject,
		NotBefore:             now.Add(time.Duration(spec.NotBeforeDays) * day),
		NotAfter:              now.Add(time.Duration(spec.NotAfterDays) * day),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, san := range spec.SANs {
		if ip := net.ParseIP(san); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, san)
		}
	}
	switch spec.Mode {
	case "selfsigned":
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leafKey.Public(), leafKey)
		if err != nil {
			return nil, err
		}
		return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}, nil
	case "ca":
		caKey, err := newKey("ecdsa")
		if err != nil {
			return nil, err
		}
		issuer := spec.IssuerCN
		if issuer == "" {
			issuer = "Czujka Lab Issuing CA"
		}
		ca := &x509.Certificate{
			SerialNumber:          serial(),
			Subject:               pkix.Name{CommonName: issuer, Organization: []string{"Czujka Lab"}},
			NotBefore:             now.Add(-3 * 365 * day),
			NotAfter:              now.Add(7 * 365 * day),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
		if err != nil {
			return nil, err
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafKey.Public(), caKey)
		if err != nil {
			return nil, err
		}
		return &tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: leafKey}, nil
	}
	return nil, fmt.Errorf("unknown TLS mode %q", spec.Mode)
}
