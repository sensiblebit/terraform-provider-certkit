---
page_title: "Provider: certkit"
description: |-
  Resolve certificate chains, generate CSRs, and encode/decode PKCS#12/PKCS#7 bundles.
---

# CertKit Provider

Resolve and verify TLS certificate chains, generate Certificate Signing Requests, and encode/decode PKCS#12 and PKCS#7 bundles.

## Why?

- **Chain resolution**: Fetch a leaf certificate via TLS or provide PEM, automatically discover intermediates via AIA, and verify against system, Mozilla, or custom trust stores
- **Certificate inspection**: Get SHA-256 fingerprints, Subject Key Identifiers (RFC 7093), and Authority Key Identifiers for every certificate in the chain
- **CSR generation**: Generate a CSR that copies Subject and SANs from an existing certificate, with the private key stored in state
- **CSR inspection**: Parse an existing CSR to extract subject, SANs, and key details
- **Bundle encoding**: Produce PKCS#12 (PFX) and PKCS#7 (P7B) bundles for systems that require them
- **Bundle decoding**: Parse existing PKCS#12 and PKCS#7 bundles to extract certificates, keys, and metadata

## Example Usage

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

# Resolve a certificate chain from a URL
data "certkit_certificate" "app" {
  url         = "https://example.com"
  trust_store = "mozilla"
}

output "fullchain" {
  value = data.certkit_certificate.app.fullchain_pem
}

output "leaf_skid" {
  value = data.certkit_certificate.app.skid
}
```

## Trust Stores

| Store | Description |
|---|---|
| `system` (default) | OS trust store (macOS Keychain, Linux ca-certificates, Windows CertStore) |
| `mozilla` | Embedded Mozilla CA bundle, works consistently on any OS |
| `custom` | Only the roots provided in `custom_roots_pem` |

## Resources

- [`certkit_cert_request`](resources/cert_request.md) -- Generate a CSR from a certificate (stores key in state)
- [`certkit_pkcs12`](resources/pkcs12.md) -- Encode a PKCS#12/PFX bundle (stores bundle in state)
- [`certkit_pkcs7`](resources/pkcs7.md) -- Encode a PKCS#7/P7B bundle (stores bundle in state)

## Data Sources

- [`certkit_certificate`](data-sources/certificate.md) -- Resolve and verify a certificate chain
- [`certkit_cert_request`](data-sources/cert_request.md) -- Parse and inspect a CSR
- [`certkit_pkcs12`](data-sources/pkcs12.md) -- Decode a PKCS#12/PFX bundle
- [`certkit_pkcs7`](data-sources/pkcs7.md) -- Decode a PKCS#7/P7B bundle
