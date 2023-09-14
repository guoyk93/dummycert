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

func encodePEM(kind string, buf []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  kind,
		Bytes: buf,
	})
}

type Bundle struct {
	Name           string
	PrivateKey     *rsa.PrivateKey
	PrivateKeyPEM  []byte
	Template       *x509.Certificate
	Certificate    *x509.Certificate
	CertificateDER []byte
	CertificatePEM []byte
}

type BundleOptions struct {
	CommonName string
	NotBefore  time.Time
	NotAfter   time.Time
	DNSNames   []string
}

type CreateChainOptions struct {
	Dir    string
	Bits   int
	RootCA BundleOptions
	Middle BundleOptions
	Server BundleOptions
	Client BundleOptions
}

func CreateChain(opts CreateChainOptions) (err error) {
	defer rg.Guard(&err)

	var (
		rootca = &Bundle{Name: "rootca"}
		middle = &Bundle{Name: "middle"}
		server = &Bundle{Name: "server"}
		client = &Bundle{Name: "client"}

		bundles = []*Bundle{rootca, middle, server, client}
	)

	// generate private keys
	for _, b := range bundles {
		b.PrivateKey = rg.Must(rsa.GenerateKey(rand.Reader, opts.Bits))
		b.PrivateKeyPEM = encodePEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(b.PrivateKey))
		rg.Must0(os.WriteFile(filepath.Join(opts.Dir, b.Name+".key.pem"), b.PrivateKeyPEM, 0600))
	}

	{
		rootca.Template = &x509.Certificate{
			Subject: pkix.Name{
				CommonName: opts.RootCA.CommonName,
			},
			DNSNames:     opts.RootCA.DNSNames,
			SerialNumber: big.NewInt(1),
			NotBefore:    opts.RootCA.NotBefore,
			NotAfter:     opts.RootCA.NotAfter,
			KeyUsage:     x509.KeyUsageCertSign,
			IsCA:         true,
			MaxPathLen:   2,
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
			DNSNames:     opts.Middle.DNSNames,
			SerialNumber: big.NewInt(1),
			NotBefore:    opts.Middle.NotBefore,
			NotAfter:     opts.Middle.NotAfter,
			KeyUsage:     x509.KeyUsageCertSign,
			IsCA:         true,
			MaxPathLen:   1,
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
	for _, b := range bundles {
		b.CertificatePEM = encodePEM("CERTIFICATE", b.CertificateDER)
		rg.Must0(os.WriteFile(filepath.Join(opts.Dir, b.Name+".crt.pem"), b.CertificatePEM, 0600))
	}

	// create full pem
	for _, b := range []*Bundle{server, client} {
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
