# terraform-provider-certkit

Terraform provider for certificate chain resolution, bundling, and encoding.

## Quick Start

```hcl
terraform {
  required_providers {
    certkit = {
      source  = "sensiblebit/certkit"
      version = "~> 1.0"
    }
  }
}

provider "certkit" {}

data "certkit_certificate" "app" {
  url         = "https://example.com"
  trust_store = "mozilla"
}

output "fullchain" {
  value = data.certkit_certificate.app.fullchain_pem
}
```

## Features

- **Chain resolution** -- fetch leaf certs via TLS or provide PEM, resolve intermediates via AIA, verify against system/Mozilla/custom trust stores
- **Fingerprints and identifiers** -- SHA-256 fingerprints, computed SKID (RFC 7093), embedded SKID/AKID for every certificate in the chain
- **CSR generation** -- generate a Certificate Signing Request from an existing certificate's Subject and SANs, with optional private key
- **PKCS#12 encoding** -- bundle leaf + chain + private key into a PFX file (base64-encoded)
- **PKCS#7 encoding** -- bundle certificates into a certs-only P7B file (base64-encoded)
- **No external dependencies** -- pure Go, no OpenSSL or shell commands

## Data Sources

| Data Source | Description |
|---|---|
| `certkit_certificate` | Resolve and verify a certificate chain |
| `certkit_cert_request` | Generate a CSR from a certificate |
| `certkit_pkcs12` | Encode a PKCS#12/PFX bundle |
| `certkit_pkcs7` | Encode a PKCS#7/P7B bundle |

## Data Source: certkit_certificate

Resolves a certificate chain from a leaf certificate (fetched via TLS or provided as PEM), optionally following AIA URLs to discover intermediates, and verifies against a trust store.

### Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `url` | String | One of `url` or `leaf_pem` | HTTPS URL to fetch the leaf certificate via TLS handshake |
| `leaf_pem` | String | One of `url` or `leaf_pem` | PEM-encoded leaf certificate |
| `extra_intermediates_pem` | List(String) | No | Additional PEM-encoded intermediate certificates |
| `fetch_aia` | Bool | No | Fetch intermediates via AIA URLs (default: `true`) |
| `aia_timeout_ms` | Number | No | Timeout per AIA fetch in milliseconds (default: `2000`) |
| `aia_max_depth` | Number | No | Maximum AIA fetch depth (default: `5`) |
| `trust_store` | String | No | Trust store: `system`, `mozilla`, or `custom` (default: `system`) |
| `custom_roots_pem` | List(String) | No | PEM-encoded root certificates when `trust_store = "custom"` |
| `verify` | Bool | No | Verify the chain against the trust store (default: `true`) |
| `include_root` | Bool | No | Include root in `fullchain_pem` output (default: `true`) |
| `colon_separated` | Bool | No | Use colon-separated hex for identifiers (default: `true`) |

### Attributes

| Name | Type | Description |
|---|---|---|
| `cert_pem` | String | Leaf certificate PEM |
| `chain_pem` | String | Leaf + intermediates PEM |
| `fullchain_pem` | String | Leaf + intermediates + root PEM |
| `sha256_fingerprint` | String | SHA-256 fingerprint of the leaf |
| `skid` | String | Leaf Subject Key Identifier (RFC 7093, computed) |
| `skid_embedded` | String | Leaf Subject Key Identifier (from certificate extension) |
| `akid` | String | Leaf Authority Key Identifier (RFC 7093 SKID of issuer) |
| `akid_embedded` | String | Leaf Authority Key Identifier (from certificate extension) |
| `intermediates` | List(Object) | Intermediate certificates with `cert_pem`, `sha256_fingerprint`, `skid`, `skid_embedded`, `akid`, `akid_embedded` |
| `roots` | List(Object) | Root certificates with same attributes as intermediates |
| `warnings` | List(String) | Non-fatal warnings (e.g., AIA fetch failures) |

## Data Source: certkit_cert_request

Generates a Certificate Signing Request by copying Subject and SANs (DNS, IP, URI) from an existing certificate.

### Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `cert_pem` | String | Yes | PEM-encoded certificate to copy Subject and SANs from |
| `private_key_pem` | String | No | PEM-encoded private key for signing. If omitted, an EC P-256 key is auto-generated |

### Attributes

| Name | Type | Description |
|---|---|---|
| `cert_request_pem` | String | PEM-encoded CSR |
| `private_key_pem` | String, Sensitive | Private key used (provided or auto-generated) |
| `key_algorithm` | String | Algorithm: `ECDSA`, `RSA`, or `Ed25519` |

## Data Source: certkit_pkcs12

Encodes a certificate, CA chain, and private key into a PKCS#12/PFX bundle.

### Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `cert_pem` | String | Yes | PEM-encoded leaf certificate |
| `private_key_pem` | String | Yes | PEM-encoded private key (Sensitive) |
| `ca_certs_pem` | List(String) | No | PEM-encoded CA certificates to include |
| `password` | String | No | Password for PKCS#12 encryption (Sensitive, default: empty) |

### Attributes

| Name | Type | Description |
|---|---|---|
| `content` | String, Sensitive | Base64-encoded PKCS#12/PFX bundle |

## Data Source: certkit_pkcs7

Encodes certificates into a certs-only PKCS#7/P7B bundle (no private key).

### Arguments

| Name | Type | Required | Description |
|---|---|---|---|
| `cert_pem` | String | No | PEM-encoded primary certificate |
| `ca_certs_pem` | List(String) | No | PEM-encoded CA certificates to include |

At least one of `cert_pem` or `ca_certs_pem` must be set.

### Attributes

| Name | Type | Description |
|---|---|---|
| `content` | String | Base64-encoded PKCS#7/P7B bundle |

## Examples

### Fetch and resolve a certificate chain

```hcl
data "certkit_certificate" "app" {
  url         = "https://example.com"
  trust_store = "mozilla"
}

output "chain" {
  value = data.certkit_certificate.app.fullchain_pem
}
```

### Resolve with custom roots (offline/airgapped)

```hcl
data "certkit_certificate" "internal" {
  leaf_pem   = file("certs/leaf.pem")
  fetch_aia  = false
  trust_store = "custom"

  extra_intermediates_pem = [file("certs/intermediate.pem")]
  custom_roots_pem        = [file("certs/root.pem")]
}
```

### Generate a CSR from an existing certificate

```hcl
data "certkit_cert_request" "renewal" {
  cert_pem = data.certkit_certificate.app.cert_pem
}

output "csr" {
  value = data.certkit_cert_request.renewal.cert_request_pem
}
```

### Create a PKCS#12 bundle

```hcl
data "certkit_pkcs12" "bundle" {
  cert_pem        = data.certkit_certificate.app.cert_pem
  private_key_pem = file("certs/key.pem")
  ca_certs_pem    = [for i in data.certkit_certificate.app.intermediates : i.cert_pem]
  password        = "changeit"
}

output "pfx" {
  value     = data.certkit_pkcs12.bundle.content
  sensitive = true
}
```

### Create a PKCS#7 bundle

```hcl
data "certkit_pkcs7" "bundle" {
  cert_pem     = data.certkit_certificate.app.cert_pem
  ca_certs_pem = [for i in data.certkit_certificate.app.intermediates : i.cert_pem]
}

output "p7b" {
  value = data.certkit_pkcs7.bundle.content
}
```

---

## Technical Reference

### SKID Calculation

The `skid` attribute is computed using RFC 7093 Section 2 Method 1: the leftmost 160 bits of the SHA-256 hash of the public key BIT STRING (excluding tag, length, and unused-bits octet). This produces a 20-byte identifier that is consistent across all certificates for the same key, regardless of what the issuing CA embeds.

The `skid_embedded` attribute returns whatever the CA placed in the Subject Key Identifier extension, which is typically SHA-1 (20 bytes) but may be full SHA-256 (32 bytes) for newer CAs.

### Trust Stores

| Store | Description |
|---|---|
| `system` | OS trust store (macOS Keychain, Linux ca-certificates, Windows CertStore) |
| `mozilla` | Embedded Mozilla CA bundle (via [rootcerts](https://github.com/breml/rootcerts)), works on any OS |
| `custom` | Only the roots provided in `custom_roots_pem` |

### Development

```bash
# Build
go build -o terraform-provider-certkit

# Unit tests
go test -v ./internal/provider/

# Acceptance tests
TF_ACC=1 go test -v ./internal/provider/ -timeout 10m

# Coverage
TF_ACC=1 go test -coverprofile=coverage.out ./internal/provider/ && go tool cover -func=coverage.out
```

## License

MIT
