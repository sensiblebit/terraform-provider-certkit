package provider

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	smPkcs7 "github.com/smallstep/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestParsePEMCertificate(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)

	cert, err := ParsePEMCertificate([]byte(leafPEM))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("got CN=%q, want test.example.com", cert.Subject.CommonName)
	}
}

func TestParsePEMCertificates_empty(t *testing.T) {
	_, err := ParsePEMCertificates([]byte("not a cert"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestCertFingerprint(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	fp := CertFingerprint(cert)
	if len(fp) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("fingerprint length %d, want 64", len(fp))
	}
}

func TestCertToPEM(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	cert, _ := ParsePEMCertificate([]byte(leafPEM))

	pem := CertToPEM(cert)
	if len(pem) == 0 {
		t.Error("empty PEM output")
	}

	// Round-trip
	cert2, err := ParsePEMCertificate([]byte(pem))
	if err != nil {
		t.Fatal(err)
	}
	if cert2.Subject.CommonName != cert.Subject.CommonName {
		t.Error("round-trip CN mismatch")
	}
}

func TestBundle_customRoots(t *testing.T) {
	// Build a 3-tier PKI
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intBytes, _ := x509.CreateCertificate(rand.Reader, intTemplate, caCert, &intKey.PublicKey, caKey)
	intCert, _ := x509.ParseCertificate(intBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	result, err := Bundle(leafCert, BundleOptions{
		ExtraIntermediates: []*x509.Certificate{intCert},
		FetchAIA:           false,
		TrustStore:         "custom",
		CustomRoots:        []*x509.Certificate{caCert},
		Verify:             true,
		IncludeRoot:        true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Intermediates) != 1 {
		t.Errorf("expected 1 intermediate, got %d", len(result.Intermediates))
	}
	if result.Intermediates[0].Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("intermediate CN=%q", result.Intermediates[0].Subject.CommonName)
	}
	if len(result.Roots) != 1 {
		t.Errorf("expected 1 root, got %d", len(result.Roots))
	}
	if result.Roots[0].Subject.CommonName != "Test Root CA" {
		t.Errorf("root CN=%q", result.Roots[0].Subject.CommonName)
	}
}

func TestBundle_mozillaRoots(t *testing.T) {
	// Fetch a real leaf cert from google.com and verify it against Mozilla roots
	leaf, err := FetchLeafFromURL("https://google.com", 5000)
	if err != nil {
		t.Skipf("cannot connect to google.com: %v", err)
	}

	result, err := Bundle(leaf, BundleOptions{
		FetchAIA:    true,
		AIATimeoutMs: 5000,
		AIAMaxDepth: 5,
		TrustStore:  "mozilla",
		Verify:      true,
		IncludeRoot: true,
	})
	if err != nil {
		t.Fatalf("Mozilla trust store verification failed: %v", err)
	}

	if len(result.Intermediates) == 0 {
		t.Error("expected at least 1 intermediate")
	}
	if len(result.Roots) == 0 {
		t.Error("expected at least 1 root")
	}
}

func TestBundle_verifyFails(t *testing.T) {
	// Leaf with no intermediates, no matching root => should fail
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "orphan.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	_, err := Bundle(cert, BundleOptions{
		FetchAIA:   false,
		TrustStore: "custom",
		Verify:     true,
	})
	if err == nil {
		t.Error("expected verification error for orphan cert")
	}
}

func TestCertSKID_RFC7093(t *testing.T) {
	_, _, leafPEM := generateTestPKI(t)
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	skid := CertSKID(leaf)
	if skid == "" {
		t.Fatal("CertSKID returned empty string")
	}

	// RFC 7093 Method 1: leftmost 160 bits of SHA-256 = 20 bytes
	// 20 bytes = 40 hex chars + 19 colons = 59 chars
	if len(skid) != 59 {
		t.Errorf("SKID length %d, want 59 (20 bytes colon-separated)", len(skid))
	}

	// Verify it matches manual computation: truncated SHA-256 of the public key BIT STRING
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(leaf.RawSubjectPublicKeyInfo, &spki)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(spki.PublicKey.Bytes)
	expected := colonHex(hash[:20]) // leftmost 160 bits
	if skid != expected {
		t.Errorf("SKID mismatch:\n  got:  %s\n  want: %s", skid, expected)
	}
}

func TestCertSKIDEmbedded(t *testing.T) {
	caPEM, _, leafPEM := generateTestPKI(t)

	ca, _ := ParsePEMCertificate([]byte(caPEM))
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	// Verify embedded SKID format (colon-separated hex)
	caSKID := CertSKIDEmbedded(ca)
	if caSKID != "" && (!strings.Contains(caSKID, ":") || len(caSKID) < 5) {
		t.Errorf("CA embedded SKID format unexpected: %q", caSKID)
	}

	leafAKID := CertAKIDEmbedded(leaf)
	if leafAKID != "" && (!strings.Contains(leafAKID, ":") || len(leafAKID) < 5) {
		t.Errorf("Leaf embedded AKID format unexpected: %q", leafAKID)
	}
}

func TestCertSKID_vs_Embedded(t *testing.T) {
	// Verify that computed RFC 7093 SKID and SHA-1 embedded SKID produce
	// different values even though both are 20 bytes.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Compute SHA-1 SKID (what most CAs currently embed)
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	asn1.Unmarshal(pubKeyDER, &spki)
	sha1Hash := sha1.Sum(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha1Hash[:], // SHA-1 embedded SKID
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	computed := CertSKID(cert)         // RFC 7093: truncated SHA-256, 20 bytes
	embedded := CertSKIDEmbedded(cert) // whatever the CA put in (SHA-1 here)

	// Both are 20 bytes / 59 chars, but different values (SHA-1 vs truncated SHA-256)
	if len(computed) != 59 {
		t.Errorf("computed SKID length %d, want 59", len(computed))
	}
	if len(embedded) != 59 {
		t.Errorf("embedded SKID length %d, want 59", len(embedded))
	}
	if computed == embedded {
		t.Error("computed (truncated SHA-256) should differ from embedded (SHA-1)")
	}

	// Verify each matches its expected value
	expectedEmbedded := colonHex(sha1Hash[:])
	if embedded != expectedEmbedded {
		t.Errorf("embedded SKID mismatch:\n  got:  %s\n  want: %s", embedded, expectedEmbedded)
	}
	sha256Hash := sha256.Sum256(spki.PublicKey.Bytes)
	expectedComputed := colonHex(sha256Hash[:20]) // RFC 7093: leftmost 160 bits
	if computed != expectedComputed {
		t.Errorf("computed SKID mismatch:\n  got:  %s\n  want: %s", computed, expectedComputed)
	}

	t.Logf("Computed SKID (RFC 7093, truncated SHA-256): %s", computed)
	t.Logf("Embedded SKID (SHA-1):                       %s", embedded)
}

func TestCertSKID_RFC7093Embedded(t *testing.T) {
	// When a CA embeds an RFC 7093 SKID (truncated SHA-256, 20 bytes),
	// _skid and _skid_embedded should match.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	asn1.Unmarshal(pubKeyDER, &spki)
	sha256Hash := sha256.Sum256(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "modern-ca"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha256Hash[:20], // RFC 7093: truncated SHA-256, 20 bytes
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	computed := CertSKID(cert)
	embedded := CertSKIDEmbedded(cert)

	// Both should be 20 bytes / 59 chars and identical
	if computed != embedded {
		t.Errorf("when CA embeds RFC 7093 SKID, computed and embedded should match:\n  computed: %s\n  embedded: %s", computed, embedded)
	}
	if len(computed) != 59 {
		t.Errorf("computed length %d, want 59", len(computed))
	}
}

func TestCertSKID_FullSHA256Embedded(t *testing.T) {
	// When a CA embeds a full 32-byte SHA-256 SKID (non-standard),
	// _skid (20 bytes) and _skid_embedded (32 bytes) should differ.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	asn1.Unmarshal(pubKeyDER, &spki)
	sha256Hash := sha256.Sum256(spki.PublicKey.Bytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "full-sha256-ca"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: sha256Hash[:], // Full 32-byte SHA-256 (non-standard)
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	computed := CertSKID(cert)
	embedded := CertSKIDEmbedded(cert)

	// Computed is 20 bytes (59 chars), embedded is 32 bytes (95 chars)
	if len(computed) != 59 {
		t.Errorf("computed length %d, want 59", len(computed))
	}
	if len(embedded) != 95 {
		t.Errorf("embedded length %d, want 95", len(embedded))
	}
	if computed == embedded {
		t.Error("truncated computed should differ from full embedded")
	}

	// But the computed value should be a prefix of the embedded value
	// (both start with the same SHA-256 hash, just different lengths)
	if !strings.HasPrefix(embedded, computed[:len(computed)-1]) {
		// The first 19 bytes (57 chars) + colon prefix should match
		t.Logf("Note: computed=%s", computed)
		t.Logf("Note: embedded=%s", embedded)
	}
}

func TestFetchLeafFromURL(t *testing.T) {
	cert, err := FetchLeafFromURL("https://google.com", 5000)
	if err != nil {
		t.Skipf("cannot connect to google.com: %v", err)
	}
	if cert.IsCA {
		t.Error("expected leaf cert, got CA")
	}
	if cert.Subject.CommonName == "" {
		t.Error("empty CN")
	}
}

func TestFetchLeafFromURL_withPort(t *testing.T) {
	cert, err := FetchLeafFromURL("https://google.com:443", 5000)
	if err != nil {
		t.Skipf("cannot connect to google.com:443: %v", err)
	}
	if cert.IsCA {
		t.Error("expected leaf cert, got CA")
	}
}

func TestFetchLeafFromURL_badHost(t *testing.T) {
	_, err := FetchLeafFromURL("https://this-does-not-exist.invalid", 2000)
	if err == nil {
		t.Error("expected error for non-existent host")
	}
}

func TestColonHex(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0x5c, 0x15, 0x76}, "5c:15:76"},
		{[]byte{0x00}, "00"},
		{[]byte{0xff, 0x00, 0xab}, "ff:00:ab"},
		{nil, ""},
	}
	for _, tt := range tests {
		got := colonHex(tt.input)
		if got != tt.expected {
			t.Errorf("colonHex(%x) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParsePEMPrivateKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKey_PKCS8(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKey_invalid(t *testing.T) {
	_, err := ParsePEMPrivateKey([]byte("not a key"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestEncodePKCS12_roundTrip(t *testing.T) {
	// Generate a self-signed cert + key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pkcs12-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	password := "test-password"
	pfxData, err := EncodePKCS12(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxData) == 0 {
		t.Fatal("empty PKCS#12 data")
	}

	// Decode it back
	decodedKey, decodedCert, err := gopkcs12.Decode(pfxData, password)
	if err != nil {
		t.Fatal(err)
	}
	if decodedCert.Subject.CommonName != "pkcs12-test" {
		t.Errorf("got CN=%q", decodedCert.Subject.CommonName)
	}
	if _, ok := decodedKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", decodedKey)
	}
}

func TestEncodePKCS12_withChain(t *testing.T) {
	// Build a 2-tier PKI: CA -> leaf
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "P12 Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.p12.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	pfxData, err := EncodePKCS12(leafKey, leafCert, []*x509.Certificate{caCert}, "pass")
	if err != nil {
		t.Fatal(err)
	}

	_, decodedCert, caCerts, err := gopkcs12.DecodeChain(pfxData, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if decodedCert.Subject.CommonName != "leaf.p12.test" {
		t.Errorf("leaf CN=%q", decodedCert.Subject.CommonName)
	}
	if len(caCerts) != 1 {
		t.Errorf("expected 1 CA cert, got %d", len(caCerts))
	}
}

func TestEncodePKCS7_roundTrip(t *testing.T) {
	caPEM, intPEM, leafPEM := generateTestPKI(t)
	ca, _ := ParsePEMCertificate([]byte(caPEM))
	intermediate, _ := ParsePEMCertificate([]byte(intPEM))
	leaf, _ := ParsePEMCertificate([]byte(leafPEM))

	derData, err := EncodePKCS7([]*x509.Certificate{leaf, intermediate, ca})
	if err != nil {
		t.Fatal(err)
	}
	if len(derData) == 0 {
		t.Fatal("empty PKCS#7 data")
	}

	// Parse it back
	p7, err := smPkcs7.Parse(derData)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.Certificates) != 3 {
		t.Errorf("expected 3 certs, got %d", len(p7.Certificates))
	}
}

func TestEncodePKCS7_empty(t *testing.T) {
	_, err := EncodePKCS7(nil)
	if err == nil {
		t.Error("expected error for empty cert list")
	}
}

func TestGenerateCSR_withKey(t *testing.T) {
	leaf, key := generateLeafWithSANs(t)

	csrPEM, keyPEM, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}

	// keyPEM should be empty when caller provides the key
	if keyPEM != "" {
		t.Error("expected empty keyPEM when private key is provided")
	}

	// Parse and verify CSR
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	// Verify Subject copied
	if csr.Subject.CommonName != leaf.Subject.CommonName {
		t.Errorf("CN=%q, want %q", csr.Subject.CommonName, leaf.Subject.CommonName)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "Test Org" {
		t.Errorf("Organization=%v, want [Test Org]", csr.Subject.Organization)
	}

	// Verify DNS SANs copied
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}

	// Verify IP SANs copied
	if len(csr.IPAddresses) != 2 {
		t.Errorf("IPAddresses count=%d, want 2", len(csr.IPAddresses))
	}

	// Verify URI SANs copied
	if len(csr.URIs) != 1 || csr.URIs[0].String() != "spiffe://example.com/workload" {
		t.Errorf("URIs=%v, want [spiffe://example.com/workload]", csr.URIs)
	}
}

func TestGenerateCSR_autoGenerate(t *testing.T) {
	leaf, _ := generateLeafWithSANs(t)

	csrPEM, keyPEM, err := GenerateCSR(leaf, nil)
	if err != nil {
		t.Fatal(err)
	}

	// keyPEM should be non-empty (auto-generated)
	if keyPEM == "" {
		t.Fatal("expected non-empty keyPEM for auto-generated key")
	}

	// Verify auto-generated key is EC P-256 in PKCS#8 format
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("failed to decode key PEM or wrong block type")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsedKey)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %v", ecKey.Curve.Params().Name)
	}

	// Parse and verify CSR
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	// Verify Subject and SANs match leaf
	if csr.Subject.CommonName != leaf.Subject.CommonName {
		t.Errorf("CN=%q, want %q", csr.Subject.CommonName, leaf.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}
}

// --- New unit tests for coverage ---

func TestParsePEMPrivateKey_RSAPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	parsed, err := ParsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePEMPrivateKey_PKCS8Error(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})

	_, err := ParsePEMPrivateKey(pemBytes)
	if err == nil {
		t.Error("expected error for invalid PKCS#8 data")
	}
	if !strings.Contains(err.Error(), "PKCS#8") {
		t.Errorf("error should mention PKCS#8, got: %v", err)
	}
}

func TestParsePEMPrivateKey_unsupportedBlockType(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("whatever")})

	_, err := ParsePEMPrivateKey(pemBytes)
	if err == nil {
		t.Error("expected error for unsupported block type")
	}
	if !strings.Contains(err.Error(), "unsupported PEM block type") {
		t.Errorf("error should mention unsupported PEM block type, got: %v", err)
	}
}

func TestParsePEMCertificates_mixedBlockTypes(t *testing.T) {
	// Create a PEM bundle with a PRIVATE KEY block followed by a CERTIFICATE block
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mixed-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	var pemData []byte
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})...)

	certs, err := ParsePEMCertificates(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert (skipping non-CERTIFICATE block), got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "mixed-test" {
		t.Errorf("CN=%q, want mixed-test", certs[0].Subject.CommonName)
	}
}

func TestParsePEMCertificates_invalidDER(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage DER")})

	_, err := ParsePEMCertificates(pemData)
	if err == nil {
		t.Error("expected error for invalid certificate DER")
	}
	if !strings.Contains(err.Error(), "parsing certificate") {
		t.Errorf("error should mention parsing certificate, got: %v", err)
	}
}

func TestParsePEMCertificate_errorPassthrough(t *testing.T) {
	_, err := ParsePEMCertificate([]byte("not valid PEM"))
	if err == nil {
		t.Error("expected error from ParsePEMCertificate")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("expected 'no certificates found' error, got: %v", err)
	}
}

func TestBundle_twoCertChain(t *testing.T) {
	// CA -> leaf (no intermediate)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Two-Tier CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "two-tier-leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	result, err := Bundle(leafCert, BundleOptions{
		FetchAIA:   false,
		TrustStore: "custom",
		CustomRoots: []*x509.Certificate{caCert},
		Verify:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2-cert chain: [leaf, root] — no intermediates
	if len(result.Intermediates) != 0 {
		t.Errorf("expected 0 intermediates, got %d", len(result.Intermediates))
	}
	if len(result.Roots) != 1 {
		t.Errorf("expected 1 root, got %d", len(result.Roots))
	}
	if result.Roots[0].Subject.CommonName != "Two-Tier CA" {
		t.Errorf("root CN=%q", result.Roots[0].Subject.CommonName)
	}
}

func TestBundle_unknownTrustStore(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	_, err := Bundle(cert, BundleOptions{
		FetchAIA:   false,
		TrustStore: "invalid",
		Verify:     true,
	})
	if err == nil {
		t.Error("expected error for unknown trust_store")
	}
	if !strings.Contains(err.Error(), "unknown trust_store") {
		t.Errorf("error should mention unknown trust_store, got: %v", err)
	}
}

func TestBundle_verifyFalsePassthrough(t *testing.T) {
	// Build CA -> leaf, pass extra intermediates, verify=false
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "NoVerify CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "noverify-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	result, err := Bundle(leafCert, BundleOptions{
		ExtraIntermediates: []*x509.Certificate{caCert},
		FetchAIA:           false,
		TrustStore:         "custom",
		Verify:             false,
	})
	if err != nil {
		t.Fatal(err)
	}

	// With verify=false, intermediates should be passed through
	if len(result.Intermediates) != 1 {
		t.Errorf("expected 1 intermediate passthrough, got %d", len(result.Intermediates))
	}
	// Roots should be nil (no verification)
	if result.Roots != nil {
		t.Errorf("expected nil roots with verify=false, got %d", len(result.Roots))
	}
}

func TestEncodePKCS12_unsupportedKeyType(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	// Pass a non-crypto key type
	_, err := EncodePKCS12(struct{}{}, cert, nil, "pass")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "unsupported private key type") {
		t.Errorf("error should mention unsupported private key type, got: %v", err)
	}
}

func TestExtractPublicKeyBitString_invalidDER(t *testing.T) {
	_, err := extractPublicKeyBitString([]byte("garbage"))
	if err == nil {
		t.Error("expected error for invalid DER")
	}
	if !strings.Contains(err.Error(), "parsing SubjectPublicKeyInfo") {
		t.Errorf("error should mention parsing SubjectPublicKeyInfo, got: %v", err)
	}
}

func TestCertSKID_errorReturnsEmpty(t *testing.T) {
	// Create a cert with zeroed RawSubjectPublicKeyInfo
	cert := &x509.Certificate{
		RawSubjectPublicKeyInfo: []byte{},
	}
	skid := CertSKID(cert)
	if skid != "" {
		t.Errorf("expected empty string for invalid SPKI, got %q", skid)
	}
}

func TestFetchLeafFromURL_invalidURL(t *testing.T) {
	_, err := FetchLeafFromURL("://bad", 2000)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "parsing URL") {
		t.Errorf("error should mention parsing URL, got: %v", err)
	}
}

func TestFetchCertFromURL_http404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := srv.Client()
	_, err := fetchCertFromURL(client, srv.URL)
	if err == nil {
		t.Error("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error should mention HTTP 404, got: %v", err)
	}
}

func TestFetchCertFromURL_DER(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "der-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(certBytes)
	}))
	defer srv.Close()

	client := srv.Client()
	cert, err := fetchCertFromURL(client, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "der-test" {
		t.Errorf("CN=%q, want der-test", cert.Subject.CommonName)
	}
}

func TestFetchCertFromURL_PEM(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pem-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(pemBytes)
	}))
	defer srv.Close()

	client := srv.Client()
	cert, err := fetchCertFromURL(client, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "pem-test" {
		t.Errorf("CN=%q, want pem-test", cert.Subject.CommonName)
	}
}

func TestFetchCertFromURL_garbage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not a certificate"))
	}))
	defer srv.Close()

	client := srv.Client()
	_, err := fetchCertFromURL(client, srv.URL)
	if err == nil {
		t.Error("expected error for garbage body")
	}
	if !strings.Contains(err.Error(), "could not parse as DER") {
		t.Errorf("error should mention DER/PEM parse failure, got: %v", err)
	}
}

func TestFetchAIACertificates_maxDepthZero(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "depth-zero"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{"http://example.com/ca.cer"},
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	fetched, warnings := FetchAIACertificates(cert, 1000, 0)
	if len(fetched) != 0 {
		t.Errorf("expected 0 fetched certs with maxDepth=0, got %d", len(fetched))
	}
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings with maxDepth=0, got %d", len(warnings))
	}
}

func TestFetchAIACertificates_duplicateURLs(t *testing.T) {
	// Serve a DER cert from the test server
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Issuer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerBytes, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)

	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(issuerBytes)
	}))
	defer srv.Close()

	// Create cert with duplicate AIA URLs
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "dup-aia-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IssuingCertificateURL: []string{srv.URL + "/ca.cer", srv.URL + "/ca.cer"},
	}
	issuerCert, _ := x509.ParseCertificate(issuerBytes)
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	fetched, _ := FetchAIACertificates(leafCert, 2000, 5)
	if len(fetched) != 1 {
		t.Errorf("expected 1 fetched cert (deduped), got %d", len(fetched))
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 HTTP fetch (deduped), got %d", fetchCount)
	}
}

func TestCertSKIDEmbedded_empty(t *testing.T) {
	cert := &x509.Certificate{
		SubjectKeyId: nil,
	}
	if got := CertSKIDEmbedded(cert); got != "" {
		t.Errorf("expected empty string for nil SubjectKeyId, got %q", got)
	}
}

func TestCertAKIDEmbedded_empty(t *testing.T) {
	cert := &x509.Certificate{
		AuthorityKeyId: nil,
	}
	if got := CertAKIDEmbedded(cert); got != "" {
		t.Errorf("expected empty string for nil AuthorityKeyId, got %q", got)
	}
}

func TestGenerateCSR_nonSignerKey(t *testing.T) {
	leaf, _ := generateLeafWithSANs(t)
	// struct{} doesn't implement crypto.Signer
	_, _, err := GenerateCSR(leaf, struct{}{})
	if err == nil {
		t.Error("expected error for non-Signer key")
	}
	if !strings.Contains(err.Error(), "does not implement crypto.Signer") {
		t.Errorf("error should mention crypto.Signer, got: %v", err)
	}
}

func TestKeyAlgorithmName(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name     string
		key      interface{}
		expected string
	}{
		{"ECDSA", ecKey, "ECDSA"},
		{"RSA", rsaKey, "RSA"},
		{"Ed25519", edKey, "Ed25519"},
		{"nil", nil, "unknown"},
		{"unsupported", struct{}{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KeyAlgorithmName(tt.key)
			if got != tt.expected {
				t.Errorf("KeyAlgorithmName(%T) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestPublicKeyAlgorithmName(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name     string
		key      interface{}
		expected string
	}{
		{"ECDSA", &ecKey.PublicKey, "ECDSA"},
		{"RSA", &rsaKey.PublicKey, "RSA"},
		{"Ed25519", edPub, "Ed25519"},
		{"nil", nil, "unknown"},
		{"unsupported", struct{}{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PublicKeyAlgorithmName(tt.key)
			if got != tt.expected {
				t.Errorf("PublicKeyAlgorithmName(%T) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestParsePEMCertificateRequest(t *testing.T) {
	leaf, key := generateLeafWithSANs(t)
	csrPEM, _, err := GenerateCSR(leaf, key)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParsePEMCertificateRequest([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CN=%q, want test.example.com", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames count=%d, want 2", len(csr.DNSNames))
	}
}

func TestParsePEMCertificateRequest_invalidPEM(t *testing.T) {
	_, err := ParsePEMCertificateRequest([]byte("not valid PEM"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "no PEM block found") {
		t.Errorf("error should mention no PEM block, got: %v", err)
	}
}

func TestParsePEMCertificateRequest_wrongBlockType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("whatever")})
	_, err := ParsePEMCertificateRequest(pemData)
	if err == nil {
		t.Error("expected error for wrong block type")
	}
	if !strings.Contains(err.Error(), "expected CERTIFICATE REQUEST") {
		t.Errorf("error should mention expected block type, got: %v", err)
	}
}

func TestParsePEMCertificateRequest_invalidDER(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")})
	_, err := ParsePEMCertificateRequest(pemData)
	if err == nil {
		t.Error("expected error for invalid DER")
	}
	if !strings.Contains(err.Error(), "parsing certificate request") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

// Suppress unused import warnings
var _ = fmt.Sprintf
var _ = strings.Contains
