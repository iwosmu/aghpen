package httpfp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// buildTLSInfo describes the handshake and the leaf certificate. hostname is
// the name the scanner asked for; it is empty when the scan went by IP, and
// then HostMismatch stays false because there is no name to compare with.
func buildTLSInfo(st *tls.ConnectionState, hostname string, now time.Time) *model.TLSInfo {
	ti := &model.TLSInfo{
		Version: tls.VersionName(st.Version),
		Cipher:  tls.CipherSuiteName(st.CipherSuite),
		SANs:    []string{},
	}
	if len(st.PeerCertificates) == 0 {
		return ti
	}
	c := st.PeerCertificates[0]
	ti.SubjectCN = c.Subject.CommonName
	ti.SubjectOrg = strings.Join(c.Subject.Organization, ", ")
	ti.SANs = append(ti.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		ti.SANs = append(ti.SANs, ip.String())
	}
	if len(ti.SANs) > 100 {
		ti.SANs = ti.SANs[:100]
	}
	ti.Issuer = c.Issuer.CommonName
	if ti.Issuer == "" {
		ti.Issuer = strings.Join(c.Issuer.Organization, ", ")
	}
	if ti.Issuer == "" {
		ti.Issuer = c.Issuer.String()
	}
	ti.NotBefore = c.NotBefore.UTC()
	ti.NotAfter = c.NotAfter.UTC()
	if c.SerialNumber != nil {
		ti.Serial = strings.ToUpper(c.SerialNumber.Text(16))
	}
	sum := sha256.Sum256(c.Raw)
	ti.SHA256 = hex.EncodeToString(sum[:])
	ti.SelfSigned = bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
	ti.Expired = now.After(c.NotAfter)
	ti.DaysLeft = int(math.Floor(c.NotAfter.Sub(now).Hours() / 24))
	if hostname != "" {
		ti.HostMismatch = c.VerifyHostname(hostname) != nil
	}
	ti.KeyType, ti.KeyBits = keyInfo(c)
	return ti
}

func keyInfo(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return c.PublicKeyAlgorithm.String(), 0
}
