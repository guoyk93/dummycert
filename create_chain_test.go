package dummycert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/guoyk93/rg"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateChain(t *testing.T) {
	dir, err := os.MkdirTemp("", "github-guoyk93-dummycert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	bundleCA := CertificateOptions{
		CommonName: "noname",
		NotBefore:  time.Now(),
	}
	bundleCA.NotAfter = bundleCA.NotBefore.Add(time.Hour)

	bundleLeaf := bundleCA
	bundleLeaf.DNSNames = []string{"localhost"}

	err = CreateChain(CreateChainOptions{
		Dir:    dir,
		Bits:   2048,
		RootCA: bundleCA,
		Middle: bundleCA,
		Server: bundleLeaf,
		Client: bundleLeaf,
	})
	require.NoError(t, err)

	caBuf := rg.Must(os.ReadFile(filepath.Join(dir, "rootca.crt.pem")))
	caBlock, _ := pem.Decode(caBuf)

	caPool := x509.NewCertPool()
	caPool.AddCert(rg.Must(x509.ParseCertificate(caBlock.Bytes)))

	s := &http.Server{
		Addr: ":19999",
		TLSConfig: &tls.Config{
			ClientCAs:  caPool.Clone(),
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.Write([]byte("OK"))
		}),
	}
	go s.ListenAndServeTLS(
		filepath.Join(dir, "server.full-crt.pem"),
		filepath.Join(dir, "server.key.pem"),
	)
	defer s.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				RootCAs: caPool.Clone(),
				Certificates: []tls.Certificate{
					rg.Must(
						tls.LoadX509KeyPair(
							filepath.Join(dir, "client.full-crt.pem"),
							filepath.Join(dir, "client.key.pem"),
						),
					),
				},
			},
		},
	}

	res := rg.Must(client.Get("https://localhost:19999/hello"))
	body := rg.Must(io.ReadAll(res.Body))
	res.Body.Close()
	require.Equal(t, "OK", string(body))
}
