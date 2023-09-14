package dummycert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/guoyk93/rg"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type keyPair struct {
	Name           string
	PrivateKey     *rsa.PrivateKey
	PrivateKeyPEM  []byte
	Template       *x509.Certificate
	Certificate    *x509.Certificate
	CertificateDER []byte
	CertificatePEM []byte
}

type KeyPairOptions struct {
	CommonName string
	NotBefore  time.Time
	NotAfter   time.Time
	DNSNames   []string
}

type CreateChainOptions struct {
	Dir    string
	Bits   int
	RootCA KeyPairOptions
	Middle KeyPairOptions
	Server KeyPairOptions
	Client KeyPairOptions
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
			Subject: pkix.Name{
				CommonName: opts.RootCA.CommonName,
			},
			DNSNames:              opts.RootCA.DNSNames,
			SerialNumber:          big.NewInt(1),
			NotBefore:             opts.RootCA.NotBefore,
			NotAfter:              opts.RootCA.NotAfter,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            2,
		}
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
			Subject: pkix.Name{
				CommonName: opts.Middle.CommonName,
			},
			DNSNames:              opts.Middle.DNSNames,
			SerialNumber:          big.NewInt(1),
			NotBefore:             opts.Middle.NotBefore,
			NotAfter:              opts.Middle.NotAfter,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}

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
			Subject: pkix.Name{
				CommonName: opts.Server.CommonName,
			},
			SerialNumber: big.NewInt(1),
			DNSNames:     opts.Server.DNSNames,
			NotBefore:    opts.Server.NotBefore,
			NotAfter:     opts.Server.NotAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
		}
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
			Subject: pkix.Name{
				CommonName: opts.Client.CommonName,
			},
			SerialNumber: big.NewInt(1),
			DNSNames:     opts.Client.DNSNames,
			NotBefore:    opts.Client.NotBefore,
			NotAfter:     opts.Client.NotAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
		}
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
