package media

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeBinaryFromFile writes a script that simply cats a JSON payload
// file to stdout. The plain `echo` form used elsewhere in this
// package mangles multi-line PEM blocks; this variant avoids quoting
// hazards entirely.
func fakeBinaryFromFile(t *testing.T, payload []byte) string {
	t.Helper()
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "out.json")
	if err := os.WriteFile(jsonPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "fake.bat")
		body := "@echo off\r\ntype \"" + jsonPath + "\"\r\nexit /B 0\r\n"
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := filepath.Join(dir, "fake.sh")
	body := "#!/bin/sh\ncat '" + jsonPath + "'\nexit 0\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// genCert produces a self-signed leaf cert + its PEM bytes for the
// trust-store fixture and a string-list payload for the c2pa-rs JSON.
func genCert(t *testing.T, serial int64) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "vertguard-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes, key
}

// makePayload builds the c2pa-rs JSON shape including the signing
// chain under signing_certs.
func makePayload(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	res := map[string]any{
		"has_manifest":    true,
		"signature_valid": true,
		"signer":          nil,
		"claims_count":    1,
		"format":          "image/png",
		"errors":          []string{},
		"warnings":        []string{},
		"manifest_summary": map[string]any{},
		"signing_certs":   []string{string(certPEM)},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeAnchor(t *testing.T, dir string, pemBytes []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "anchor.pem"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
}

// crlBytes builds a minimal PEM CRL containing serial revocation entries.
func crlBytes(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, serials ...*big.Int) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   s,
			RevocationTime: time.Now(),
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

func TestVerify_TrustVerdict_Table(t *testing.T) {
	cert, certPEM, key := genCert(t, 4242)
	payload := makePayload(t, certPEM)
	bin := fakeBinaryFromFile(t, payload)

	anchorsDir := t.TempDir()
	writeAnchor(t, anchorsDir, certPEM)
	emptyDir := t.TempDir()

	crlPath := filepath.Join(t.TempDir(), "revoked.crl")
	if err := os.WriteFile(crlPath, crlBytes(t, cert, key, big.NewInt(4242)), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		anchors    string
		crl        string
		wantStatus string
	}{
		{"trusted_with_matching_anchor", anchorsDir, "", TrustStatusTrusted},
		{"untrusted_with_empty_dir", emptyDir, "", TrustStatusUntrusted},
		{"revoked_serial_in_crl", anchorsDir, crlPath, TrustStatusRevoked},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, err := NewTrustStore(tc.anchors)
			if err != nil {
				t.Fatalf("trust store: %v", err)
			}
			var rl *RevocationList
			if tc.crl != "" {
				rl, err = NewRevocationList(tc.crl)
				if err != nil {
					t.Fatalf("crl: %v", err)
				}
			}
			v := New(Config{
				BinaryPath:  bin,
				Timeout:     5 * time.Second,
				MaxFileSize: 1024,
				TrustStore:  ts,
				Revocation:  rl,
			})
			res, err := v.Verify(context.Background(), strings.NewReader("hello"), "x.png")
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if res.TrustStatus != tc.wantStatus {
				t.Fatalf("trust_status = %q, want %q", res.TrustStatus, tc.wantStatus)
			}
		})
	}
}

func TestVerify_UnsignedManifest(t *testing.T) {
	bin := fakeBinary(t, `{"has_manifest":false,"signature_valid":false,"signer":null,"claims_count":0,"format":"","errors":[],"warnings":[],"manifest_summary":{}}`, 0)
	ts, _ := NewTrustStore(t.TempDir())
	v := New(Config{BinaryPath: bin, Timeout: 5 * time.Second, MaxFileSize: 1024, TrustStore: ts})
	res, err := v.Verify(context.Background(), strings.NewReader("nope"), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.TrustStatus != TrustStatusUnsigned {
		t.Fatalf("trust_status = %q, want unsigned", res.TrustStatus)
	}
}
