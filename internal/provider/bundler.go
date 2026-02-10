package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/breml/rootcerts/embedded"
	"github.com/smallstep/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// BundleResult holds the resolved chain and metadata.
type BundleResult struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
	Roots         []*x509.Certificate
	Warnings      []string
}

// BundleOptions configures chain resolution.
type BundleOptions struct {
	ExtraIntermediates []*x509.Certificate
	FetchAIA           bool
	AIATimeoutMs       int
	AIAMaxDepth        int
	TrustStore         string // "system", "mozilla", "custom"
	CustomRoots        []*x509.Certificate
	Verify             bool
	IncludeRoot        bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() BundleOptions {
	return BundleOptions{
		FetchAIA:     true,
		AIATimeoutMs: 2000,
		AIAMaxDepth:  5,
		TrustStore:   "system",
		Verify:       true,
		IncludeRoot:  true,
	}
}

// ParsePEMCertificates parses all certificates from a PEM bundle.
func ParsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return certs, nil
}

// ParsePEMCertificate parses a single certificate from PEM data.
func ParsePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	certs, err := ParsePEMCertificates(pemData)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// FetchLeafFromURL connects to the given HTTPS URL via TLS and returns the
// leaf (server) certificate from the handshake.
func FetchLeafFromURL(rawURL string, timeoutMs int) (*x509.Certificate, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName: host,
		},
	}
	dialer.NetDialer = &net.Dialer{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("TLS dial to %s:%s: %w", host, port, err)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned by %s:%s", host, port)
	}
	return certs[0], nil
}

// FetchAIACertificates follows AIA CA Issuers URLs to fetch intermediate certificates.
func FetchAIACertificates(cert *x509.Certificate, timeoutMs int, maxDepth int) ([]*x509.Certificate, []string) {
	var fetched []*x509.Certificate
	var warnings []string

	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	seen := make(map[string]bool)
	queue := []*x509.Certificate{cert}

	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		current := queue[0]
		queue = queue[1:]

		for _, url := range current.IssuingCertificateURL {
			if seen[url] {
				continue
			}
			seen[url] = true

			issuer, err := fetchCertFromURL(client, url)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("AIA fetch failed for %s: %v", url, err))
				continue
			}
			fetched = append(fetched, issuer)
			queue = append(queue, issuer)
		}
	}
	return fetched, warnings
}

// fetchCertFromURL fetches a single certificate (DER or PEM) from a URL.
func fetchCertFromURL(client *http.Client, url string) (*x509.Certificate, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}

	// Try DER first (most AIA URLs serve DER)
	cert, err := x509.ParseCertificate(body)
	if err == nil {
		return cert, nil
	}

	// Fall back to PEM
	cert, pemErr := ParsePEMCertificate(body)
	if pemErr == nil {
		return cert, nil
	}

	return nil, fmt.Errorf("could not parse as DER (%v) or PEM (%v)", err, pemErr)
}

// Bundle resolves the full certificate chain for a leaf certificate.
func Bundle(leaf *x509.Certificate, opts BundleOptions) (*BundleResult, error) {
	result := &BundleResult{Leaf: leaf}

	// Build intermediate pool
	intermediatePool := x509.NewCertPool()
	var allIntermediates []*x509.Certificate

	for _, cert := range opts.ExtraIntermediates {
		intermediatePool.AddCert(cert)
		allIntermediates = append(allIntermediates, cert)
	}

	if opts.FetchAIA {
		aiaCerts, warnings := FetchAIACertificates(leaf, opts.AIATimeoutMs, opts.AIAMaxDepth)
		result.Warnings = append(result.Warnings, warnings...)
		for _, cert := range aiaCerts {
			intermediatePool.AddCert(cert)
			allIntermediates = append(allIntermediates, cert)
		}
	}

	// Build root pool
	var rootPool *x509.CertPool
	switch opts.TrustStore {
	case "system":
		var err error
		rootPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("loading system cert pool: %w", err)
		}
	case "mozilla":
		rootPool = x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM([]byte(embedded.MozillaCACertificatesPEM())) {
			return nil, fmt.Errorf("failed to parse embedded Mozilla root certificates")
		}
	case "custom":
		rootPool = x509.NewCertPool()
		for _, cert := range opts.CustomRoots {
			rootPool.AddCert(cert)
		}
	default:
		return nil, fmt.Errorf("unknown trust_store: %q", opts.TrustStore)
	}

	// Verify
	if opts.Verify {
		verifyOpts := x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         rootPool,
		}
		chains, err := leaf.Verify(verifyOpts)
		if err != nil {
			return nil, fmt.Errorf("chain verification failed: %w", err)
		}

		// Pick shortest valid chain
		best := chains[0]
		for _, chain := range chains[1:] {
			if len(chain) < len(best) {
				best = chain
			}
		}

		// Extract intermediates and root from verified chain
		// Chain order: [leaf, intermediate1, ..., root]
		if len(best) > 2 {
			result.Intermediates = best[1 : len(best)-1]
		}
		if len(best) > 1 {
			result.Roots = []*x509.Certificate{best[len(best)-1]}
		}
	} else {
		// No verification — just pass through what we have
		result.Intermediates = allIntermediates
		// No root extraction without verification
	}

	return result, nil
}

// CertToPEM encodes a certificate as PEM.
func CertToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// CertFingerprint returns the SHA-256 fingerprint of a certificate as a hex string.
func CertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash)
}

// CertSKID computes a Subject Key Identifier from the certificate's
// public key per RFC 7093 Section 2 Method 1: the leftmost 160 bits
// of the SHA-256 hash of the BIT STRING value of subjectPublicKey
// (excluding tag, length, and unused-bits octet). The result is 20
// bytes, the same length as a SHA-1 SKID, ensuring compatibility.
func CertSKID(cert *x509.Certificate) string {
	pubKeyBytes, err := extractPublicKeyBitString(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(pubKeyBytes)
	return colonHex(hash[:20]) // RFC 7093: leftmost 160 bits
}

// CertSKIDEmbedded returns the Subject Key Identifier as stored in the
// certificate extension, as a colon-separated hex string. This may be
// SHA-1 (20 bytes) or SHA-256 (32 bytes) depending on the issuing CA.
// Returns empty string if the extension is not present.
func CertSKIDEmbedded(cert *x509.Certificate) string {
	if len(cert.SubjectKeyId) == 0 {
		return ""
	}
	return colonHex(cert.SubjectKeyId)
}

// CertAKIDEmbedded returns the Authority Key Identifier as stored in the
// certificate extension, as a colon-separated hex string. This matches the
// issuing CA's embedded SKID and may be SHA-1 or SHA-256.
// Returns empty string if the extension is not present.
func CertAKIDEmbedded(cert *x509.Certificate) string {
	if len(cert.AuthorityKeyId) == 0 {
		return ""
	}
	return colonHex(cert.AuthorityKeyId)
}

// extractPublicKeyBitString parses a DER-encoded SubjectPublicKeyInfo and
// returns the raw public key bytes (the BIT STRING value, excluding the
// unused-bits octet).
func extractPublicKeyBitString(spkiDER []byte) ([]byte, error) {
	// SubjectPublicKeyInfo ::= SEQUENCE {
	//   algorithm AlgorithmIdentifier,
	//   subjectPublicKey BIT STRING
	// }
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(spkiDER, &spki)
	if err != nil {
		return nil, fmt.Errorf("parsing SubjectPublicKeyInfo: %w", err)
	}
	return spki.PublicKey.Bytes, nil
}

// ParsePEMPrivateKey parses a PEM-encoded private key (PKCS#1, PKCS#8, or EC).
func ParsePEMPrivateKey(pemData []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key data")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#8 private key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// EncodePKCS12 creates a PKCS#12/PFX bundle from a private key, leaf cert,
// CA chain, and password. Returns the DER-encoded PKCS#12 data.
func EncodePKCS12(privateKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		return nil, fmt.Errorf("unsupported private key type %T", privateKey)
	}
	return gopkcs12.Modern.Encode(privateKey, leaf, caCerts, password)
}

// EncodePKCS7 creates a certs-only PKCS#7/P7B bundle from a certificate chain.
// Returns the DER-encoded PKCS#7 SignedData structure.
func EncodePKCS7(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates to encode")
	}
	var derBytes []byte
	for _, cert := range certs {
		derBytes = append(derBytes, cert.Raw...)
	}
	return pkcs7.DegenerateCertificate(derBytes)
}

// GenerateCSR creates a Certificate Signing Request that copies Subject, DNSNames,
// IPAddresses, and URIs from the given leaf certificate. If privateKey is nil,
// a new EC P-256 key is generated. Returns the PEM-encoded CSR and, if a key was
// auto-generated, its PEM-encoded PKCS#8 private key (empty string if caller provided the key).
func GenerateCSR(leaf *x509.Certificate, privateKey crypto.PrivateKey) (csrPEM string, keyPEM string, err error) {
	var signer crypto.Signer
	autoGenerated := false

	if privateKey != nil {
		var ok bool
		signer, ok = privateKey.(crypto.Signer)
		if !ok {
			return "", "", fmt.Errorf("private key does not implement crypto.Signer")
		}
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", "", fmt.Errorf("generating EC P-256 key: %w", err)
		}
		signer = key
		autoGenerated = true
	}

	template := &x509.CertificateRequest{
		Subject:     leaf.Subject,
		DNSNames:    leaf.DNSNames,
		IPAddresses: leaf.IPAddresses,
		URIs:        leaf.URIs,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return "", "", fmt.Errorf("creating CSR: %w", err)
	}

	csrPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))

	if autoGenerated {
		keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
		if err != nil {
			return "", "", fmt.Errorf("encoding private key: %w", err)
		}
		keyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		}))
	}

	return csrPEM, keyPEM, nil
}

// colonHex formats a byte slice as colon-separated uppercase hex.
func colonHex(b []byte) string {
	h := hex.EncodeToString(b)
	var parts []string
	for i := 0; i < len(h); i += 2 {
		end := i + 2
		if end > len(h) {
			end = len(h)
		}
		parts = append(parts, h[i:end])
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ":"
		}
		result += p
	}
	return result
}
