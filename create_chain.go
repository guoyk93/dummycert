package dummycert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/guoyk93/rg"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cleanDNSNames(ss []string) []string {
	var ret []string
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s != "" {
			ret = append(ret, s)
		}
	}
	return ret
}

func cleanIPAddresses(ss []string) []net.IP {
	var ret []net.IP
	for _, s := range ss {
		p := net.ParseIP(strings.TrimSpace(s))
		if p != nil {
			ret = append(ret, p)
		}
	}
	return ret
}

type keyPair struct {
	Name           string
	PrivateKey     *rsa.PrivateKey
	PrivateKeyPEM  []byte
	Template       *x509.Certificate
	Certificate    *x509.Certificate
	CertificateDER []byte
	CertificatePEM []byte
}

type CertificateOptions struct {
	CommonName   string
	SerialNumber int64
	NotBefore    time.Time
	NotAfter     time.Time
	DNSNames     []string
	IPAddresses  []string
}

func (co CertificateOptions) Apply(crt *x509.Certificate) {
	crt.Subject.CommonName = co.CommonName
	crt.Subject.Organization = []string{"github.com/guoyk93/dummycert"}
	crt.SerialNumber = big.NewInt(co.SerialNumber)
	crt.NotBefore = co.NotBefore
	crt.NotAfter = co.NotAfter
	crt.DNSNames = cleanDNSNames(co.DNSNames)
	crt.IPAddresses = cleanIPAddresses(co.IPAddresses)
}

type CreateChainOptions struct {
	Dir    string
	Bits   int
	RootCA CertificateOptions
	Middle CertificateOptions
	Server CertificateOptions
	Client CertificateOptions
}

// CreateChain creates a dummy certificate chain
func CreateChain(opts CreateChainOptions) (err error) {
	defer rg.Guard(&err)

	var (
		rootca = &keyPair{Name: "rootca"}
		middle = &keyPair{Name: "middle"}
		server = &keyPair{Name: "server"}
		client = &keyPair{Name: "client"}

		keyPairs = []*keyPair{rootca, middle, server, client}
	)

	// generate private keys
	for _, b := range keyPairs {
		b.PrivateKey = rg.Must(rsa.GenerateKey(rand.Reader, opts.Bits))
		b.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(b.PrivateKey),
		})
		rg.Must0(os.WriteFile(filepath.Join(opts.Dir, b.Name+".key.pem"), b.PrivateKeyPEM, 0600))
	}

	{
		rootca.Template = &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            2,
		}
		opts.RootCA.Apply(rootca.Template)

		rootca.CertificateDER = rg.Must(
			x509.CreateCertificate(
				rand.Reader,
				rootca.Template,
				rootca.Template,
				&rootca.PrivateKey.PublicKey,
				rootca.PrivateKey,
			),
		)
		rootca.Certificate = rg.Must(x509.ParseCertificate(rootca.CertificateDER))
	}

	{
		middle.Template = &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}
		opts.Middle.Apply(middle.Template)

		middle.CertificateDER = rg.Must(
			x509.CreateCertificate(
				rand.Reader,
				middle.Template,
				rootca.Certificate,
				&middle.PrivateKey.PublicKey,
				rootca.PrivateKey,
			),
		)
		middle.Certificate = rg.Must(x509.ParseCertificate(middle.CertificateDER))
	}

	{
		server.Template = &x509.Certificate{
			SerialNumber: big.NewInt(1),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		opts.Server.Apply(server.Template)

		server.CertificateDER = rg.Must(
			x509.CreateCertificate(
				rand.Reader,
				server.Template,
				middle.Certificate,
				&server.PrivateKey.PublicKey,
				middle.PrivateKey,
			),
		)
		server.Certificate = rg.Must(x509.ParseCertificate(server.CertificateDER))
	}

	{
		client.Template = &x509.Certificate{
			SerialNumber: big.NewInt(1),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		opts.Client.Apply(client.Template)

		client.CertificateDER = rg.Must(
			x509.CreateCertificate(
				rand.Reader,
				client.Template,
				middle.Certificate,
				&client.PrivateKey.PublicKey,
				middle.PrivateKey,
			),
		)
		client.Certificate = rg.Must(x509.ParseCertificate(client.CertificateDER))
	}

	// create certificate pem
	for _, b := range keyPairs {
		b.CertificatePEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b.CertificateDER,
		})
		rg.Must0(os.WriteFile(filepath.Join(opts.Dir, b.Name+".crt.pem"), b.CertificatePEM, 0600))
	}

	// create full pem
	for _, b := range []*keyPair{server, client} {
		rg.Must0(
			os.WriteFile(
				filepath.Join(opts.Dir, b.Name+".full-crt.pem"),
				bytes.Join([][]byte{
					bytes.TrimSpace(b.CertificatePEM),
					bytes.TrimSpace(middle.CertificatePEM),
					bytes.TrimSpace(rootca.CertificatePEM),
				}, []byte{'\n'}),
				0600,
			),
		)
	}

	return
}
