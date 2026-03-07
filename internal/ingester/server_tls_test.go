package ingester

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/config"
	redis "github.com/clusterpulse/cluster-controller/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestServerTLS(t *testing.T) {
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "tls.crt")
	keyFile := filepath.Join(certDir, "tls.key")
	caPool := generateTestCert(t, certFile, keyFile)

	cfg := &config.Config{
		IngesterEnabled:    true,
		IngesterPort:       0, // unused, we call Start with a specific port
		IngesterTLSEnabled: true,
		IngesterTLSCert:    certFile,
		IngesterTLSKey:     keyFile,
	}

	srv := NewServer(cfg, &redis.Client{})
	defer srv.Stop()

	// Listen on random port
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()

	go func() {
		_ = srv.grpcServer.Serve(lis)
	}()

	// Dial with TLS using the test CA
	tlsCfg := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS12,
	}
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Verify the connection reaches Ready state
	ctx := t.Context()
	conn.Connect()
	for {
		state := conn.GetState()
		if state == 2 { // connectivity.Ready
			break
		}
		if !conn.WaitForStateChange(ctx, state) {
			t.Fatal("context cancelled before connection became ready")
		}
	}
}

// generateTestCert creates a self-signed cert/key pair and returns the CA pool.
func generateTestCert(t *testing.T, certPath, keyPath string) *x509.CertPool {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return pool
}
